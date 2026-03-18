package tools

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/joakimcarlsson/ai/agent"
	"github.com/joakimcarlsson/ai/tool"
)

const (
	ddgHTMLURL   = "https://html.duckduckgo.com/html/"
	ddgUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

var (
	resultBlockRe = regexp.MustCompile(
		`class="result results_links results_links_deep web-result\s*"`,
	)
	titleReLnk = regexp.MustCompile(
		`class="result__a"\s+href="([^"]+)"[^>]*>([^<]+)`,
	)
	snippetReLnk = regexp.MustCompile(
		`(?s)class="result__snippet"[^>]*>(.*?)</a>`,
	)
	htmlTagRe = regexp.MustCompile(`<[^>]+>`)
)

type WebSearchParams struct {
	Query string `json:"query"           description:"The search query"`
	Limit int    `json:"limit,omitempty" description:"Max results to return (default 5)"`
}

type WebSearchTool struct {
	client    *http.Client
	searchURL string
}

func NewWebSearch() *WebSearchTool {
	return &WebSearchTool{
		client:    &http.Client{Timeout: 30 * time.Second},
		searchURL: ddgHTMLURL,
	}
}

func NewWebSearchWithEndpoints(_, searchURL string) *WebSearchTool {
	return &WebSearchTool{
		client:    &http.Client{Timeout: 30 * time.Second},
		searchURL: searchURL,
	}
}

func (t *WebSearchTool) Info() tool.ToolInfo {
	return tool.NewToolInfo(
		"web_search",
		`Search the web via DuckDuckGo and return ranked results with title, URL, and snippet.
Use to research targets, look up CVEs by product name, find known vulnerability patterns, locate public exploit code, or discover breach disclosures related to the target.`,
		WebSearchParams{},
	)
}

func (t *WebSearchTool) Run(ctx context.Context, params tool.ToolCall) (tool.ToolResponse, error) {
	input, err := agent.ParseToolInput[WebSearchParams](params.Input)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid input: %v", err)), nil
	}

	if input.Query == "" {
		return tool.NewTextErrorResponse("query is required"), nil
	}

	limit := 5
	if input.Limit > 0 {
		limit = input.Limit
	}

	results, err := t.search(ctx, input.Query, limit)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("search failed: %v", err)), nil
	}

	if len(results) == 0 {
		return tool.NewTextResponse("No results found."), nil
	}

	return tool.NewJSONResponse(results), nil
}

type searchResult struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Snippet string `json:"snippet"`
}

func (t *WebSearchTool) search(ctx context.Context, query string, limit int) ([]searchResult, error) {
	form := url.Values{}
	form.Set("q", query)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		t.searchURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", ddgUserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching results: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return parseHTMLResults(string(body), limit), nil
}

func parseHTMLResults(body string, limit int) []searchResult {
	locs := resultBlockRe.FindAllStringIndex(body, -1)
	if len(locs) == 0 {
		return nil
	}

	var results []searchResult
	for i, loc := range locs {
		end := len(body)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		block := body[loc[0]:end]

		titleMatch := titleReLnk.FindStringSubmatch(block)
		if titleMatch == nil {
			continue
		}
		rawURL := html.UnescapeString(titleMatch[1])
		title := html.UnescapeString(strings.TrimSpace(titleMatch[2]))

		var snippet string
		if sm := snippetReLnk.FindStringSubmatch(block); sm != nil {
			snippet = htmlTagRe.ReplaceAllString(sm[1], "")
			snippet = html.UnescapeString(strings.TrimSpace(snippet))
		}

		results = append(results, searchResult{
			Title:   title,
			URL:     rawURL,
			Snippet: snippet,
		})
		if len(results) >= limit {
			break
		}
	}

	return results
}
