package tools

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/joakimcarlsson/ai/agent"
	"github.com/joakimcarlsson/ai/tool"
)

const (
	maxProbeWireBody = 2 << 20
	maxProbeLLMBody  = 4096
)

type probeJar struct {
	mu  sync.Mutex
	jar *cookiejar.Jar
}

func newProbeJar() *probeJar {
	j, _ := cookiejar.New(nil)
	return &probeJar{jar: j}
}

func (p *probeJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.jar.SetCookies(u, cookies)
}

func (p *probeJar) Cookies(u *url.URL) []*http.Cookie {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.jar.Cookies(u)
}

func (p *probeJar) clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.jar, _ = cookiejar.New(nil)
}

type HTTPProbeParams struct {
	URL             string            `json:"url"                       desc:"The URL to send the request to"`
	Method          string            `json:"method,omitempty"          desc:"HTTP method (default: GET)"`
	Headers         map[string]string `json:"headers,omitempty"         desc:"Custom request headers"`
	Body            string            `json:"body,omitempty"            desc:"Raw request body"`
	FollowRedirects bool              `json:"followRedirects,omitempty" desc:"Follow redirects (default: false, returns 3xx as-is)"`
	TimeoutSeconds  int               `json:"timeoutSeconds,omitempty"  desc:"Timeout in seconds (default: 30, max: 120)"`
	ClearCookies    bool              `json:"clearCookies,omitempty"    desc:"Clear the cookie jar before sending"`
}

type redirectHop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"statusCode"`
}

type httpProbeResult struct {
	URL           string            `json:"url"`
	Method        string            `json:"method"`
	StatusCode    int               `json:"statusCode"`
	Status        string            `json:"status"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body"`
	BodyTruncated bool              `json:"bodyTruncated"`
	BodyBytes     int               `json:"bodyBytes"`
	RedirectChain []redirectHop     `json:"redirectChain,omitempty"`
	Cookies       []string          `json:"cookies,omitempty"`
}

type HTTPProbeTool struct {
	jar       *probeJar
	transport http.RoundTripper
}

func NewHTTPProbe() *HTTPProbeTool {
	return &HTTPProbeTool{
		jar: newProbeJar(),
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func (t *HTTPProbeTool) Info() tool.ToolInfo {
	return tool.NewToolInfo(
		"http_probe",
		`Send an arbitrary HTTP request and return the full response including status code, headers, and body.
Supports custom methods (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD), request headers, and a raw body.
Cookies are persisted across calls — use clearCookies to reset the jar.
By default redirects are NOT followed; set followRedirects to true to chase them and receive the full redirect chain.
Use for active endpoint probing, authentication flows, SSRF testing, or replaying modified captured requests.`,
		HTTPProbeParams{},
	)
}

func (t *HTTPProbeTool) Run(ctx context.Context, params tool.ToolCall) (tool.ToolResponse, error) {
	input, err := agent.ParseToolInput[HTTPProbeParams](params.Input)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid input: %v", err)), nil
	}

	if input.URL == "" {
		return tool.NewTextErrorResponse("url is required"), nil
	}

	method := strings.ToUpper(input.Method)
	if method == "" {
		method = http.MethodGet
	}

	if input.ClearCookies {
		t.jar.clear()
	}

	timeout := 30 * time.Second
	if input.TimeoutSeconds > 0 {
		timeout = time.Duration(min(input.TimeoutSeconds, 120)) * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var bodyReader io.Reader
	if input.Body != "" {
		bodyReader = strings.NewReader(input.Body)
	}

	req, err := http.NewRequestWithContext(ctx, method, input.URL, bodyReader)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid request: %v", err)), nil
	}

	for k, v := range input.Headers {
		req.Header.Set(k, v)
	}

	var chain []redirectHop

	client := &http.Client{
		Jar:       t.jar,
		Transport: t.transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !input.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			prev := via[len(via)-1]
			statusCode := 0
			if req.Response != nil {
				statusCode = req.Response.StatusCode
			}
			chain = append(chain, redirectHop{
				URL:        prev.URL.String(),
				StatusCode: statusCode,
			})
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("request failed: %v", err)), nil
	}
	defer resp.Body.Close()

	wireBody, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeWireBody))
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("failed to read response body: %v", err)), nil
	}

	bodyBytes := len(wireBody)
	truncated := false
	bodyStr := ""

	if !utf8.Valid(wireBody) {
		bodyStr = fmt.Sprintf("[binary data, %d bytes]", bodyBytes)
	} else {
		s := string(wireBody)
		if len(s) > maxProbeLLMBody {
			bodyStr = s[:maxProbeLLMBody] + "\n... [truncated]"
			truncated = true
		} else {
			bodyStr = s
		}
	}

	flatHeaders := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		flatHeaders[k] = strings.Join(vs, ", ")
	}

	parsedURL, _ := url.Parse(input.URL)
	cookies := t.jar.Cookies(parsedURL)
	cookieStrs := make([]string, 0, len(cookies))
	for _, c := range cookies {
		cookieStrs = append(cookieStrs, c.Name+"="+c.Value)
	}

	result := httpProbeResult{
		URL:           input.URL,
		Method:        method,
		StatusCode:    resp.StatusCode,
		Status:        resp.Status,
		Headers:       flatHeaders,
		Body:          bodyStr,
		BodyTruncated: truncated,
		BodyBytes:     bodyBytes,
		RedirectChain: chain,
		Cookies:       cookieStrs,
	}

	return tool.NewJSONResponse(result), nil
}
