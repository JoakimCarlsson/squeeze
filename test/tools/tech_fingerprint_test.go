package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sqtools "github.com/joakimcarlsson/squeeze/internal/tools"
	"github.com/joakimcarlsson/squeeze/internal/tools/fingerprint"
)

type fingerprintResult struct {
	URL          string            `json:"url"`
	StatusCode   int               `json:"status_code"`
	Technologies []fingerprint.Hit `json:"technologies"`
	Headers      map[string]string `json:"headers"`
	WAFDetected  bool              `json:"waf_detected"`
}

func runFingerprint(t *testing.T, input string) fingerprintResult {
	t.Helper()
	tool := sqtools.NewTechFingerprint()
	resp, err := tool.Run(context.Background(), makeCall("tech_fingerprint", input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}
	var result fingerprintResult
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	return result
}

func runFingerprintError(t *testing.T, input string) string {
	t.Helper()
	tool := sqtools.NewTechFingerprint()
	resp, err := tool.Run(context.Background(), makeCall("tech_fingerprint", input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatalf("expected tool error, got success: %s", resp.Content)
	}
	return resp.Content
}

func findTech(hits []fingerprint.Hit, name string) *fingerprint.Hit {
	for i := range hits {
		if hits[i].Name == name {
			return &hits[i]
		}
	}
	return nil
}

func TestTechFingerprint_Info(t *testing.T) {
	tool := sqtools.NewTechFingerprint()
	info := tool.Info()
	if info.Name != "tech_fingerprint" {
		t.Fatalf("expected name tech_fingerprint, got %s", info.Name)
	}
}

func TestTechFingerprint_EmptyURL(t *testing.T) {
	msg := runFingerprintError(t, `{"url":""}`)
	if !strings.Contains(msg, "url is required") {
		t.Errorf("expected 'url is required', got %q", msg)
	}
}

func TestTechFingerprint_InvalidURL(t *testing.T) {
	msg := runFingerprintError(t, `{"url":"not-a-url"}`)
	if msg == "" {
		t.Error("expected non-empty error for invalid url")
	}
}

func TestTechFingerprint_StatusCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	result := runFingerprint(t, fmt.Sprintf(`{"url":"%s"}`, srv.URL))
	if result.StatusCode != http.StatusTeapot {
		t.Errorf("expected status %d, got %d", http.StatusTeapot, result.StatusCode)
	}
}

func TestTechFingerprint_URLReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result := runFingerprint(t, fmt.Sprintf(`{"url":"%s"}`, srv.URL))
	if result.URL != srv.URL {
		t.Errorf("expected url %s, got %s", srv.URL, result.URL)
	}
}

func TestTechFingerprint_DetectsNginx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result := runFingerprint(t, fmt.Sprintf(`{"url":"%s"}`, srv.URL))
	if findTech(result.Technologies, "Nginx") == nil {
		t.Error("expected Nginx to be detected")
	}
}

func TestTechFingerprint_DetectsPHP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result := runFingerprint(t, fmt.Sprintf(`{"url":"%s"}`, srv.URL))
	if findTech(result.Technologies, "PHP") == nil {
		t.Error("expected PHP to be detected")
	}
}

func TestTechFingerprint_DetectsWordPress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><link rel="stylesheet" href="/wp-content/themes/test/style.css"></head><body></body></html>`)
	}))
	defer srv.Close()

	result := runFingerprint(t, fmt.Sprintf(`{"url":"%s"}`, srv.URL))
	if findTech(result.Technologies, "WordPress") == nil {
		t.Error("expected WordPress to be detected")
	}
}

func TestTechFingerprint_WAFDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "DataDome")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result := runFingerprint(t, fmt.Sprintf(`{"url":"%s"}`, srv.URL))
	if !result.WAFDetected {
		t.Error("expected waf_detected to be true for DataDome")
	}
}

func TestTechFingerprint_NoWAFOnPlainServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result := runFingerprint(t, fmt.Sprintf(`{"url":"%s"}`, srv.URL))
	if result.WAFDetected {
		t.Error("expected waf_detected to be false for plain Nginx")
	}
}

func TestTechFingerprint_HeadersReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "test-value")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result := runFingerprint(t, fmt.Sprintf(`{"url":"%s"}`, srv.URL))
	if result.Headers["X-Custom-Header"] != "test-value" {
		t.Errorf("expected X-Custom-Header in headers, got %v", result.Headers)
	}
}

func TestTechFingerprint_CustomTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result := runFingerprint(t, fmt.Sprintf(`{"url":"%s","timeout_seconds":5}`, srv.URL))
	if result.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", result.StatusCode)
	}
}
