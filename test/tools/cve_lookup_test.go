package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	sqtools "github.com/joakimcarlsson/squeeze/internal/tools"
)

type cveLookupResult struct {
	Product      string         `json:"product"`
	Version      string         `json:"version,omitempty"`
	TotalResults int            `json:"total_results"`
	CVEs         []cveEntryTest `json:"cves"`
}

type cveEntryTest struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	CVSSScore   float64  `json:"cvss_score"`
	Severity    string   `json:"severity"`
	CVSSVersion string   `json:"cvss_version"`
	Published   string   `json:"published"`
	References  []string `json:"references"`
}

func runCVELookup(t *testing.T, tl *sqtools.CVELookupTool, input string) cveLookupResult {
	t.Helper()
	resp, err := tl.Run(context.Background(), makeCall("cve_lookup", input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}
	var result cveLookupResult
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	return result
}

func runCVELookupError(t *testing.T, tl *sqtools.CVELookupTool, input string) string {
	t.Helper()
	resp, err := tl.Run(context.Background(), makeCall("cve_lookup", input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatalf("expected tool error, got success: %s", resp.Content)
	}
	return resp.Content
}

func fakeNVDResponse(vulns ...string) string {
	joined := strings.Join(vulns, ",")
	return fmt.Sprintf(`{
		"resultsPerPage": %d,
		"startIndex": 0,
		"totalResults": %d,
		"vulnerabilities": [%s]
	}`, len(vulns), len(vulns), joined)
}

func fakeVulnV31(id string, score float64, severity, desc string) string {
	return fmt.Sprintf(`{
		"cve": {
			"id": %q,
			"published": "2024-01-15T10:00:00.000",
			"descriptions": [{"lang": "en", "value": %q}],
			"metrics": {
				"cvssMetricV31": [{"cvssData": {"baseScore": %v, "baseSeverity": %q}}]
			},
			"references": [{"url": "https://nvd.nist.gov/vuln/detail/%s"}]
		}
	}`, id, desc, score, severity, id)
}

func fakeVulnV30(id string, score float64, severity string) string {
	return fmt.Sprintf(`{
		"cve": {
			"id": %q,
			"published": "2024-02-01T10:00:00.000",
			"descriptions": [{"lang": "en", "value": "v30 vuln"}],
			"metrics": {
				"cvssMetricV30": [{"cvssData": {"baseScore": %v, "baseSeverity": %q}}]
			},
			"references": [{"url": "https://example.com/%s"}]
		}
	}`, id, score, severity, id)
}

func fakeVulnV2(id string, score float64, severity string) string {
	return fmt.Sprintf(`{
		"cve": {
			"id": %q,
			"published": "2023-06-01T10:00:00.000",
			"descriptions": [{"lang": "en", "value": "v2 vuln"}],
			"metrics": {
				"cvssMetricV2": [{"cvssData": {"baseScore": %v}, "baseSeverity": %q}]
			},
			"references": [{"url": "https://example.com/%s"}]
		}
	}`, id, score, severity, id)
}

func fakeVulnNoMetrics(id string) string {
	return fmt.Sprintf(`{
		"cve": {
			"id": %q,
			"published": "2023-01-01T10:00:00.000",
			"descriptions": [{"lang": "en", "value": "no metrics"}],
			"metrics": {},
			"references": []
		}
	}`, id)
}

func TestCVELookup_Info(t *testing.T) {
	tl := sqtools.NewCVELookup()
	info := tl.Info()
	if info.Name != "cve_lookup" {
		t.Fatalf("expected name cve_lookup, got %s", info.Name)
	}
}

func TestCVELookup_EmptyProduct(t *testing.T) {
	tl := sqtools.NewCVELookup()
	msg := runCVELookupError(t, tl, `{"product":""}`)
	if !strings.Contains(msg, "product is required") {
		t.Fatalf("expected 'product is required', got: %s", msg)
	}
}

func TestCVELookup_InvalidInput(t *testing.T) {
	tl := sqtools.NewCVELookup()
	msg := runCVELookupError(t, tl, `not json`)
	if !strings.Contains(msg, "invalid input") {
		t.Fatalf("expected 'invalid input', got: %s", msg)
	}
}

func TestCVELookup_ParsesResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeNVDResponse(
			fakeVulnV31("CVE-2024-1111", 9.8, "CRITICAL", "Buffer overflow in nginx"),
			fakeVulnV31("CVE-2024-2222", 7.5, "HIGH", "Information disclosure"),
		))
	}))
	defer srv.Close()

	tl := sqtools.NewCVELookupWithURL(srv.URL)
	result := runCVELookup(t, tl, `{"product":"nginx","version":"1.24.0"}`)

	if result.Product != "nginx" {
		t.Fatalf("expected product nginx, got %s", result.Product)
	}
	if result.Version != "1.24.0" {
		t.Fatalf("expected version 1.24.0, got %s", result.Version)
	}
	if result.TotalResults != 2 {
		t.Fatalf("expected 2 results, got %d", result.TotalResults)
	}
	if result.CVEs[0].ID != "CVE-2024-1111" {
		t.Fatalf("expected first CVE CVE-2024-1111, got %s", result.CVEs[0].ID)
	}
	if result.CVEs[0].CVSSScore != 9.8 {
		t.Fatalf("expected score 9.8, got %v", result.CVEs[0].CVSSScore)
	}
	if result.CVEs[0].Description != "Buffer overflow in nginx" {
		t.Fatalf("unexpected description: %s", result.CVEs[0].Description)
	}
	if len(result.CVEs[0].References) != 1 {
		t.Fatalf("expected 1 reference, got %d", len(result.CVEs[0].References))
	}
}

func TestCVELookup_SortedByCVSSDescending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeNVDResponse(
			fakeVulnV31("CVE-2024-LOW", 5.0, "MEDIUM", "low"),
			fakeVulnV31("CVE-2024-CRIT", 9.8, "CRITICAL", "crit"),
			fakeVulnV31("CVE-2024-HIGH", 7.5, "HIGH", "high"),
		))
	}))
	defer srv.Close()

	tl := sqtools.NewCVELookupWithURL(srv.URL)
	result := runCVELookup(t, tl, `{"product":"test"}`)

	if result.CVEs[0].CVSSScore != 9.8 {
		t.Fatalf("expected first score 9.8, got %v", result.CVEs[0].CVSSScore)
	}
	if result.CVEs[1].CVSSScore != 7.5 {
		t.Fatalf("expected second score 7.5, got %v", result.CVEs[1].CVSSScore)
	}
	if result.CVEs[2].CVSSScore != 5.0 {
		t.Fatalf("expected third score 5.0, got %v", result.CVEs[2].CVSSScore)
	}
}

func TestCVELookup_CVSSPriority_V31(t *testing.T) {
	vuln := `{
		"cve": {
			"id": "CVE-2024-MULTI",
			"published": "2024-01-01T00:00:00.000",
			"descriptions": [{"lang": "en", "value": "multi metric"}],
			"metrics": {
				"cvssMetricV31": [{"cvssData": {"baseScore": 9.0, "baseSeverity": "CRITICAL"}}],
				"cvssMetricV30": [{"cvssData": {"baseScore": 8.0, "baseSeverity": "HIGH"}}],
				"cvssMetricV2":  [{"cvssData": {"baseScore": 7.0}, "baseSeverity": "HIGH"}]
			},
			"references": []
		}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeNVDResponse(vuln))
	}))
	defer srv.Close()

	tl := sqtools.NewCVELookupWithURL(srv.URL)
	result := runCVELookup(t, tl, `{"product":"test"}`)

	if result.CVEs[0].CVSSScore != 9.0 {
		t.Fatalf("expected v3.1 score 9.0, got %v", result.CVEs[0].CVSSScore)
	}
	if result.CVEs[0].CVSSVersion != "3.1" {
		t.Fatalf("expected cvss_version 3.1, got %s", result.CVEs[0].CVSSVersion)
	}
}

func TestCVELookup_CVSSPriority_V30(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeNVDResponse(fakeVulnV30("CVE-2024-V30", 8.5, "HIGH")))
	}))
	defer srv.Close()

	tl := sqtools.NewCVELookupWithURL(srv.URL)
	result := runCVELookup(t, tl, `{"product":"test"}`)

	if result.CVEs[0].CVSSVersion != "3.0" {
		t.Fatalf("expected cvss_version 3.0, got %s", result.CVEs[0].CVSSVersion)
	}
	if result.CVEs[0].CVSSScore != 8.5 {
		t.Fatalf("expected score 8.5, got %v", result.CVEs[0].CVSSScore)
	}
}

func TestCVELookup_CVSSPriority_V2(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeNVDResponse(fakeVulnV2("CVE-2023-V2", 6.5, "MEDIUM")))
	}))
	defer srv.Close()

	tl := sqtools.NewCVELookupWithURL(srv.URL)
	result := runCVELookup(t, tl, `{"product":"test"}`)

	if result.CVEs[0].CVSSVersion != "2.0" {
		t.Fatalf("expected cvss_version 2.0, got %s", result.CVEs[0].CVSSVersion)
	}
	if result.CVEs[0].Severity != "MEDIUM" {
		t.Fatalf("expected severity MEDIUM, got %s", result.CVEs[0].Severity)
	}
}

func TestCVELookup_NoCVSSMetrics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeNVDResponse(fakeVulnNoMetrics("CVE-2023-NONE")))
	}))
	defer srv.Close()

	tl := sqtools.NewCVELookupWithURL(srv.URL)
	result := runCVELookup(t, tl, `{"product":"test"}`)

	if result.CVEs[0].Severity != "UNKNOWN" {
		t.Fatalf("expected severity UNKNOWN, got %s", result.CVEs[0].Severity)
	}
	if result.CVEs[0].CVSSVersion != "none" {
		t.Fatalf("expected cvss_version none, got %s", result.CVEs[0].CVSSVersion)
	}
	if result.CVEs[0].CVSSScore != 0 {
		t.Fatalf("expected score 0, got %v", result.CVEs[0].CVSSScore)
	}
}

func TestCVELookup_LimitResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeNVDResponse(
			fakeVulnV31("CVE-2024-0001", 9.8, "CRITICAL", "a"),
			fakeVulnV31("CVE-2024-0002", 8.0, "HIGH", "b"),
			fakeVulnV31("CVE-2024-0003", 7.5, "HIGH", "c"),
			fakeVulnV31("CVE-2024-0004", 6.0, "MEDIUM", "d"),
			fakeVulnV31("CVE-2024-0005", 4.0, "MEDIUM", "e"),
		))
	}))
	defer srv.Close()

	tl := sqtools.NewCVELookupWithURL(srv.URL)
	result := runCVELookup(t, tl, `{"product":"test","limit":2}`)

	if result.TotalResults != 2 {
		t.Fatalf("expected 2 results, got %d", result.TotalResults)
	}
	if len(result.CVEs) != 2 {
		t.Fatalf("expected 2 CVEs, got %d", len(result.CVEs))
	}
}

func TestCVELookup_NoResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`)
	}))
	defer srv.Close()

	tl := sqtools.NewCVELookupWithURL(srv.URL)
	resp, err := tl.Run(context.Background(), makeCall("cve_lookup", `{"product":"nonexistent"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("expected non-error response, got error: %s", resp.Content)
	}
	if !strings.Contains(resp.Content, "No CVEs found") {
		t.Fatalf("expected 'No CVEs found' message, got: %s", resp.Content)
	}
}

func TestCVELookup_Cache(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, fakeNVDResponse(fakeVulnV31("CVE-2024-CACHE", 7.0, "HIGH", "cached")))
	}))
	defer srv.Close()

	tl := sqtools.NewCVELookupWithURL(srv.URL)

	_ = runCVELookup(t, tl, `{"product":"nginx"}`)
	_ = runCVELookup(t, tl, `{"product":"nginx"}`)

	if hits.Load() != 1 {
		t.Fatalf("expected 1 server hit (cached), got %d", hits.Load())
	}
}

func TestCVELookup_CacheMiss(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, fakeNVDResponse(fakeVulnV31("CVE-2024-MISS", 5.0, "MEDIUM", "miss")))
	}))
	defer srv.Close()

	tl := sqtools.NewCVELookupWithURL(srv.URL)

	_ = runCVELookup(t, tl, `{"product":"nginx"}`)
	_ = runCVELookup(t, tl, `{"product":"apache"}`)

	if hits.Load() != 2 {
		t.Fatalf("expected 2 server hits (cache miss), got %d", hits.Load())
	}
}

func TestCVELookup_VersionInQuery(t *testing.T) {
	var receivedKeyword string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKeyword = r.URL.Query().Get("keywordSearch")
		fmt.Fprint(w, fakeNVDResponse())
	}))
	defer srv.Close()

	tl := sqtools.NewCVELookupWithURL(srv.URL)
	tl.Run(context.Background(), makeCall("cve_lookup", `{"product":"nginx","version":"1.24.0"}`))

	if receivedKeyword != "nginx 1.24.0" {
		t.Fatalf("expected keywordSearch 'nginx 1.24.0', got %q", receivedKeyword)
	}
}

func TestCVELookup_VersionOmittedFromQuery(t *testing.T) {
	var receivedKeyword string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKeyword = r.URL.Query().Get("keywordSearch")
		fmt.Fprint(w, fakeNVDResponse())
	}))
	defer srv.Close()

	tl := sqtools.NewCVELookupWithURL(srv.URL)
	tl.Run(context.Background(), makeCall("cve_lookup", `{"product":"nginx"}`))

	if receivedKeyword != "nginx" {
		t.Fatalf("expected keywordSearch 'nginx', got %q", receivedKeyword)
	}
}

func TestCVELookup_APIKeyHeader(t *testing.T) {
	t.Setenv("NVD_API_KEY", "test-secret-key")

	var receivedKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("apiKey")
		fmt.Fprint(w, fakeNVDResponse())
	}))
	defer srv.Close()

	tl := sqtools.NewCVELookupWithURL(srv.URL)
	tl.Run(context.Background(), makeCall("cve_lookup", `{"product":"test"}`))

	if receivedKey != "test-secret-key" {
		t.Fatalf("expected apiKey header 'test-secret-key', got %q", receivedKey)
	}
}

func TestCVELookup_Non200Response(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	tl := sqtools.NewCVELookupWithURL(srv.URL)
	msg := runCVELookupError(t, tl, `{"product":"test"}`)

	if !strings.Contains(msg, "403") {
		t.Fatalf("expected error mentioning 403, got: %s", msg)
	}
}

func TestCVELookup_ReferencesLimited(t *testing.T) {
	vuln := `{
		"cve": {
			"id": "CVE-2024-REFS",
			"published": "2024-01-01T00:00:00.000",
			"descriptions": [{"lang": "en", "value": "many refs"}],
			"metrics": {
				"cvssMetricV31": [{"cvssData": {"baseScore": 7.0, "baseSeverity": "HIGH"}}]
			},
			"references": [
				{"url": "https://example.com/1"},
				{"url": "https://example.com/2"},
				{"url": "https://example.com/3"},
				{"url": "https://example.com/4"},
				{"url": "https://example.com/5"},
				{"url": "https://example.com/6"},
				{"url": "https://example.com/7"},
				{"url": "https://example.com/8"},
				{"url": "https://example.com/9"},
				{"url": "https://example.com/10"}
			]
		}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeNVDResponse(vuln))
	}))
	defer srv.Close()

	tl := sqtools.NewCVELookupWithURL(srv.URL)
	result := runCVELookup(t, tl, `{"product":"test"}`)

	if len(result.CVEs[0].References) != 5 {
		t.Fatalf("expected 5 references (capped), got %d", len(result.CVEs[0].References))
	}
}
