package tools

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"time"

	"github.com/joakimcarlsson/ai/agent"
	"github.com/joakimcarlsson/ai/tool"
	"github.com/joakimcarlsson/squeeze/internal/tools/fingerprint"
)

const maxFingerprintBody = 512 << 10
const wafCategoryID = 16

type TechFingerprintParams struct {
	URL            string `json:"url"                      description:"The URL to fingerprint"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" description:"Request timeout in seconds (default: 30)"`
}

type techFingerprintResult struct {
	URL          string            `json:"url"`
	StatusCode   int               `json:"status_code"`
	Technologies []fingerprint.Hit `json:"technologies"`
	Headers      map[string]string `json:"headers"`
	WAFDetected  bool              `json:"waf_detected"`
}

type TechFingerprintTool struct{}

func NewTechFingerprint() *TechFingerprintTool {
	return &TechFingerprintTool{}
}

func (t *TechFingerprintTool) Info() tool.ToolInfo {
	return tool.NewToolInfo(
		"tech_fingerprint",
		"Fingerprint a URL to identify its technology stack: web server, CMS, frameworks, CDN, WAF, and JS libraries. "+
			"Returns a list of detected technologies with versions and categories, plus a waf_detected flag. "+
			"Run early in recon to understand what you're dealing with before active probing.",
		TechFingerprintParams{},
	)
}

func (t *TechFingerprintTool) Run(ctx context.Context, params tool.ToolCall) (tool.ToolResponse, error) {
	input, err := agent.ParseToolInput[TechFingerprintParams](params.Input)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid input: %v", err)), nil
	}
	if input.URL == "" {
		return tool.NewTextErrorResponse("url is required"), nil
	}

	timeout := 30 * time.Second
	if input.TimeoutSeconds > 0 {
		timeout = time.Duration(input.TimeoutSeconds) * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, input.URL, nil)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid url: %v", err)), nil
	}
	req.Header.Set(
		"User-Agent",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	)

	resp, err := client.Do(req)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("request failed: %v", err)), nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFingerprintBody))
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("read body failed: %v", err)), nil
	}

	headers := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	db := fingerprint.Default()
	hits := db.Match(input.URL, resp.Header, resp.Cookies(), body)

	wafDetected := false
	for _, h := range hits {
		for _, cat := range h.Categories {
			if cat == wafCategoryID {
				wafDetected = true
				break
			}
		}
	}

	result := techFingerprintResult{
		URL:          input.URL,
		StatusCode:   resp.StatusCode,
		Technologies: hits,
		Headers:      headers,
		WAFDetected:  wafDetected,
	}

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("marshal result: %v", err)), nil
	}
	return tool.NewTextResponse(string(out)), nil
}
