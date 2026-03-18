package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/joakimcarlsson/ai/agent"
	"github.com/joakimcarlsson/ai/tool"
)

const (
	nvdBaseURL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	maxNVDBodySize    = 2 << 20
	nvdRequestTimeout = 30 * time.Second
	defaultCVELimit   = 10
	maxCVELimit       = 50
	maxCVERefs        = 5
)

type CVELookupParams struct {
	Product string `json:"product"           desc:"Product name to search for (e.g. 'apache http_server', 'openssl')"`
	Version string `json:"version,omitempty"  desc:"Product version to narrow results (e.g. '2.4.49'). Omit for all versions."`
	Limit   int    `json:"limit,omitempty"    desc:"Max CVEs to return sorted by severity (default 10, max 50)"`
}

type nvdResponse struct {
	ResultsPerPage  int              `json:"resultsPerPage"`
	StartIndex      int              `json:"startIndex"`
	TotalResults    int              `json:"totalResults"`
	Vulnerabilities []nvdVulnWrapper `json:"vulnerabilities"`
}

type nvdVulnWrapper struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string           `json:"id"`
	Published    string           `json:"published"`
	Descriptions []nvdDescription `json:"descriptions"`
	Metrics      nvdMetrics       `json:"metrics"`
	References   []nvdReference   `json:"references"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CvssMetricV31 []nvdCVSSMetric   `json:"cvssMetricV31"`
	CvssMetricV30 []nvdCVSSMetric   `json:"cvssMetricV30"`
	CvssMetricV2  []nvdCVSSMetricV2 `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdCVSSMetricV2 struct {
	CVSSData     nvdCVSSDataV2 `json:"cvssData"`
	BaseSeverity string        `json:"baseSeverity"`
}

type nvdCVSSDataV2 struct {
	BaseScore float64 `json:"baseScore"`
}

type nvdReference struct {
	URL string `json:"url"`
}

type cveResult struct {
	Product      string     `json:"product"`
	Version      string     `json:"version,omitempty"`
	TotalResults int        `json:"total_results"`
	CVEs         []cveEntry `json:"cves"`
}

type cveEntry struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	CVSSScore   float64  `json:"cvss_score"`
	Severity    string   `json:"severity"`
	CVSSVersion string   `json:"cvss_version"`
	Published   string   `json:"published"`
	References  []string `json:"references"`
}

type cveCacheKey struct {
	product string
	version string
}

type CVELookupTool struct {
	client  *http.Client
	baseURL string

	mu    sync.Mutex
	cache map[cveCacheKey][]cveEntry
}

func NewCVELookup() *CVELookupTool {
	return &CVELookupTool{
		client:  &http.Client{Timeout: nvdRequestTimeout},
		baseURL: nvdBaseURL,
		cache:   make(map[cveCacheKey][]cveEntry),
	}
}

func NewCVELookupWithURL(baseURL string) *CVELookupTool {
	return &CVELookupTool{
		client:  &http.Client{Timeout: nvdRequestTimeout},
		baseURL: baseURL,
		cache:   make(map[cveCacheKey][]cveEntry),
	}
}

func (t *CVELookupTool) Info() tool.ToolInfo {
	return tool.NewToolInfo(
		"cve_lookup",
		`Search the NIST National Vulnerability Database (NVD) for known CVEs affecting a product.
Returns CVEs sorted by CVSS severity score (highest first) with descriptions, scores, and references.
Use after tech_fingerprint or port_scan to check discovered technologies for known vulnerabilities.`,
		CVELookupParams{},
	)
}

func (t *CVELookupTool) Run(ctx context.Context, params tool.ToolCall) (tool.ToolResponse, error) {
	input, err := agent.ParseToolInput[CVELookupParams](params.Input)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid input: %v", err)), nil
	}

	if input.Product == "" {
		return tool.NewTextErrorResponse("product is required"), nil
	}

	limit := defaultCVELimit
	if input.Limit > 0 {
		limit = input.Limit
		if limit > maxCVELimit {
			limit = maxCVELimit
		}
	}

	key := cveCacheKey{product: strings.ToLower(input.Product), version: input.Version}

	t.mu.Lock()
	cached, ok := t.cache[key]
	t.mu.Unlock()

	var entries []cveEntry
	if ok {
		entries = cached
	} else {
		entries, err = t.fetchCVEs(ctx, input.Product, input.Version)
		if err != nil {
			return tool.NewTextErrorResponse(fmt.Sprintf("NVD query failed: %v", err)), nil
		}

		t.mu.Lock()
		t.cache[key] = entries
		t.mu.Unlock()
	}

	if len(entries) == 0 {
		return tool.NewTextResponse("No CVEs found for the specified product/version."), nil
	}

	if len(entries) > limit {
		entries = entries[:limit]
	}

	return tool.NewJSONResponse(cveResult{
		Product:      input.Product,
		Version:      input.Version,
		TotalResults: len(entries),
		CVEs:         entries,
	}), nil
}

func (t *CVELookupTool) fetchCVEs(ctx context.Context, product, version string) ([]cveEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, nvdRequestTimeout)
	defer cancel()

	queryURL, err := t.buildQueryURL(product, version)
	if err != nil {
		return nil, fmt.Errorf("building query URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	if apiKey := os.Getenv("NVD_API_KEY"); apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching NVD data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxNVDBodySize))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var nvdResp nvdResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, fmt.Errorf("parsing NVD response: %w", err)
	}

	entries := make([]cveEntry, 0, len(nvdResp.Vulnerabilities))
	for _, vuln := range nvdResp.Vulnerabilities {
		entries = append(entries, convertCVE(vuln.CVE))
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].CVSSScore > entries[j].CVSSScore
	})

	return entries, nil
}

func (t *CVELookupTool) buildQueryURL(product, version string) (string, error) {
	u, err := url.Parse(t.baseURL)
	if err != nil {
		return "", err
	}

	q := u.Query()

	keyword := product
	if version != "" {
		keyword = product + " " + version
	}
	q.Set("keywordSearch", keyword)
	q.Set("resultsPerPage", strconv.Itoa(maxCVELimit))

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func convertCVE(cve nvdCVE) cveEntry {
	entry := cveEntry{
		ID:        cve.ID,
		Published: cve.Published,
	}

	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			entry.Description = d.Value
			break
		}
	}

	switch {
	case len(cve.Metrics.CvssMetricV31) > 0:
		m := cve.Metrics.CvssMetricV31[0]
		entry.CVSSScore = m.CVSSData.BaseScore
		entry.Severity = m.CVSSData.BaseSeverity
		entry.CVSSVersion = "3.1"
	case len(cve.Metrics.CvssMetricV30) > 0:
		m := cve.Metrics.CvssMetricV30[0]
		entry.CVSSScore = m.CVSSData.BaseScore
		entry.Severity = m.CVSSData.BaseSeverity
		entry.CVSSVersion = "3.0"
	case len(cve.Metrics.CvssMetricV2) > 0:
		m := cve.Metrics.CvssMetricV2[0]
		entry.CVSSScore = m.CVSSData.BaseScore
		entry.Severity = m.BaseSeverity
		entry.CVSSVersion = "2.0"
	default:
		entry.Severity = "UNKNOWN"
		entry.CVSSVersion = "none"
	}

	for i, ref := range cve.References {
		if i >= maxCVERefs {
			break
		}
		entry.References = append(entry.References, ref.URL)
	}

	return entry
}
