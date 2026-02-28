package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sqtools "github.com/joakimcarlsson/squeeze/internal/tools"
)

type probeResult struct {
	URL           string            `json:"url"`
	Method        string            `json:"method"`
	StatusCode    int               `json:"statusCode"`
	Status        string            `json:"status"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body"`
	BodyTruncated bool              `json:"bodyTruncated"`
	BodyBytes     int               `json:"bodyBytes"`
	RedirectChain []struct {
		URL        string `json:"url"`
		StatusCode int    `json:"statusCode"`
	} `json:"redirectChain"`
	Cookies []string `json:"cookies"`
}

func runProbe(t *testing.T, input string) probeResult {
	t.Helper()
	p := sqtools.NewHTTPProbe()
	return runProbeWith(t, p, input)
}

func runProbeWith(t *testing.T, p *sqtools.HTTPProbeTool, input string) probeResult {
	t.Helper()
	resp, err := p.Run(context.Background(), makeCall("http_probe", input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}
	var result probeResult
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	return result
}

func runProbeError(t *testing.T, input string) string {
	t.Helper()
	p := sqtools.NewHTTPProbe()
	resp, err := p.Run(context.Background(), makeCall("http_probe", input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatalf("expected tool error, got success: %s", resp.Content)
	}
	return resp.Content
}

func TestHTTPProbe_Info(t *testing.T) {
	p := sqtools.NewHTTPProbe()
	info := p.Info()
	if info.Name != "http_probe" {
		t.Fatalf("expected name http_probe, got %s", info.Name)
	}
}

func TestHTTPProbe_EmptyURL(t *testing.T) {
	errMsg := runProbeError(t, `{"url":""}`)
	if !strings.Contains(errMsg, "url is required") {
		t.Errorf("expected 'url is required', got %q", errMsg)
	}
}

func TestHTTPProbe_DefaultGet(t *testing.T) {
	var receivedMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	result := runProbe(t, fmt.Sprintf(`{"url":"%s"}`, srv.URL))

	if receivedMethod != "GET" {
		t.Errorf("expected server to receive GET, got %q", receivedMethod)
	}
	if result.Method != "GET" {
		t.Errorf("expected method GET in result, got %q", result.Method)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.StatusCode)
	}
	if result.Body != "ok" {
		t.Errorf("expected body 'ok', got %q", result.Body)
	}
}

func TestHTTPProbe_PostWithBody(t *testing.T) {
	var receivedMethod string
	var receivedBody string
	var receivedContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":1}`)
	}))
	defer srv.Close()

	input := fmt.Sprintf(`{"url":"%s","method":"POST","headers":{"Content-Type":"application/json"},"body":"{\"name\":\"test\"}"}`, srv.URL)
	result := runProbe(t, input)

	if receivedMethod != "POST" {
		t.Errorf("expected POST, got %q", receivedMethod)
	}
	if receivedContentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", receivedContentType)
	}
	if receivedBody != `{"name":"test"}` {
		t.Errorf("expected body '{\"name\":\"test\"}', got %q", receivedBody)
	}
	if result.StatusCode != 201 {
		t.Errorf("expected status 201, got %d", result.StatusCode)
	}
	if result.Body != `{"id":1}` {
		t.Errorf("expected body '{\"id\":1}', got %q", result.Body)
	}
}

func TestHTTPProbe_CustomHeaders(t *testing.T) {
	var receivedAuth string
	var receivedCustom string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedCustom = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	input := fmt.Sprintf(`{"url":"%s","headers":{"Authorization":"Bearer tok123","X-Custom":"hello"}}`, srv.URL)
	runProbe(t, input)

	if receivedAuth != "Bearer tok123" {
		t.Errorf("expected Authorization 'Bearer tok123', got %q", receivedAuth)
	}
	if receivedCustom != "hello" {
		t.Errorf("expected X-Custom 'hello', got %q", receivedCustom)
	}
}

func TestHTTPProbe_FollowRedirects(t *testing.T) {
	step := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch step {
		case 0:
			step++
			w.Header().Set("Location", r.URL.Host+"/step2")
			http.Redirect(w, r, "/step2", http.StatusFound)
		case 1:
			step++
			http.Redirect(w, r, "/final", http.StatusMovedPermanently)
		default:
			fmt.Fprint(w, "done")
		}
	}))
	defer srv.Close()

	input := fmt.Sprintf(`{"url":"%s","followRedirects":true}`, srv.URL)
	result := runProbe(t, input)

	if result.StatusCode != 200 {
		t.Errorf("expected final status 200, got %d", result.StatusCode)
	}
	if result.Body != "done" {
		t.Errorf("expected body 'done', got %q", result.Body)
	}
	if len(result.RedirectChain) != 2 {
		t.Fatalf("expected 2 redirect hops, got %d", len(result.RedirectChain))
	}
	if result.RedirectChain[0].StatusCode != 302 {
		t.Errorf("expected first hop status 302, got %d", result.RedirectChain[0].StatusCode)
	}
	if result.RedirectChain[1].StatusCode != 301 {
		t.Errorf("expected second hop status 301, got %d", result.RedirectChain[1].StatusCode)
	}
}

func TestHTTPProbe_NoFollowRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusFound)
	}))
	defer srv.Close()

	input := fmt.Sprintf(`{"url":"%s"}`, srv.URL)
	result := runProbe(t, input)

	if result.StatusCode != 302 {
		t.Errorf("expected status 302, got %d", result.StatusCode)
	}
	if len(result.RedirectChain) != 0 {
		t.Errorf("expected empty redirect chain, got %d hops", len(result.RedirectChain))
	}
}

func TestHTTPProbe_CookiePersistence(t *testing.T) {
	var secondRequestCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123", Path: "/"})
			fmt.Fprint(w, "logged in")
			return
		}
		if r.URL.Path == "/protected" {
			c, err := r.Cookie("session")
			if err == nil {
				secondRequestCookie = c.Value
			}
			fmt.Fprint(w, "secret data")
			return
		}
	}))
	defer srv.Close()

	p := sqtools.NewHTTPProbe()

	runProbeWith(t, p, fmt.Sprintf(`{"url":"%s/login"}`, srv.URL))
	runProbeWith(t, p, fmt.Sprintf(`{"url":"%s/protected"}`, srv.URL))

	if secondRequestCookie != "abc123" {
		t.Errorf("expected cookie 'abc123' on second request, got %q", secondRequestCookie)
	}
}

func TestHTTPProbe_ClearCookies(t *testing.T) {
	var lastCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "tok", Value: "xyz", Path: "/"})
			fmt.Fprint(w, "set")
			return
		}
		c, err := r.Cookie("tok")
		if err == nil {
			lastCookie = c.Value
		} else {
			lastCookie = ""
		}
		fmt.Fprint(w, "check")
	}))
	defer srv.Close()

	p := sqtools.NewHTTPProbe()

	runProbeWith(t, p, fmt.Sprintf(`{"url":"%s/set"}`, srv.URL))
	runProbeWith(t, p, fmt.Sprintf(`{"url":"%s/check","clearCookies":true}`, srv.URL))

	if lastCookie != "" {
		t.Errorf("expected no cookie after clear, got %q", lastCookie)
	}
}

func TestHTTPProbe_BodyTruncation(t *testing.T) {
	largeBody := strings.Repeat("x", 8192)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, largeBody)
	}))
	defer srv.Close()

	result := runProbe(t, fmt.Sprintf(`{"url":"%s"}`, srv.URL))

	if !result.BodyTruncated {
		t.Error("expected bodyTruncated to be true")
	}
	if !strings.HasSuffix(result.Body, "[truncated]") {
		t.Error("expected body to end with [truncated]")
	}
	if result.BodyBytes != 8192 {
		t.Errorf("expected bodyBytes 8192, got %d", result.BodyBytes)
	}
}

func TestHTTPProbe_BinaryBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0x80})
	}))
	defer srv.Close()

	result := runProbe(t, fmt.Sprintf(`{"url":"%s"}`, srv.URL))

	if !strings.Contains(result.Body, "binary data") {
		t.Errorf("expected binary placeholder, got %q", result.Body)
	}
	if result.BodyBytes != 6 {
		t.Errorf("expected bodyBytes 6, got %d", result.BodyBytes)
	}
}

func TestHTTPProbe_HeadMethod(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "present")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result := runProbe(t, fmt.Sprintf(`{"url":"%s","method":"HEAD"}`, srv.URL))

	if result.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.StatusCode)
	}
	if result.Method != "HEAD" {
		t.Errorf("expected method HEAD, got %q", result.Method)
	}
	if result.BodyBytes != 0 {
		t.Errorf("expected empty body for HEAD, got %d bytes", result.BodyBytes)
	}
}

func TestHTTPProbe_ResponseHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "value1")
		w.Header().Set("X-Another", "value2")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result := runProbe(t, fmt.Sprintf(`{"url":"%s"}`, srv.URL))

	if result.Headers["X-Test"] != "value1" {
		t.Errorf("expected X-Test 'value1', got %q", result.Headers["X-Test"])
	}
	if result.Headers["X-Another"] != "value2" {
		t.Errorf("expected X-Another 'value2', got %q", result.Headers["X-Another"])
	}
}
