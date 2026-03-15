package tools

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/joakimcarlsson/ai/agent"
	"github.com/joakimcarlsson/ai/tool"

	htmltomarkdown "github.com/JohannesKaufmann/html-to-markdown/v2"
)

const maxFetchBodySize = 1 << 20 // 1MB

var titleRe = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)

type FetchParams struct {
	URL string `json:"url" description:"The URL to fetch"`
}

type FetchTool struct{}

func NewFetch() *FetchTool {
	return &FetchTool{}
}

func (t *FetchTool) Info() tool.ToolInfo {
	return tool.NewToolInfo(
		"fetch_webpage",
		`Fetch a URL and return the page content as cleaned Markdown.
Use to read CVE detail pages, vendor advisories, documentation, or any web page relevant to the engagement.
Strips navigation, ads, and boilerplate.
For testing HTTP endpoints with full request/response control, use http_probe instead.`,
		FetchParams{},
	)
}

func (t *FetchTool) Run(ctx context.Context, params tool.ToolCall) (tool.ToolResponse, error) {
	input, err := agent.ParseToolInput[FetchParams](params.Input)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid input: %v", err)), nil
	}

	if input.URL == "" {
		return tool.NewTextErrorResponse("url is required"), nil
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, input.URL, nil)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid url: %v", err)), nil
	}
	req.Header.Set(
		"User-Agent",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("fetch failed: %v", err)), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return tool.NewTextErrorResponse(
			fmt.Sprintf("HTTP %d %s", resp.StatusCode, resp.Status),
		), nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBodySize))
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("read body failed: %v", err)), nil
	}

	htmlContent := string(body)

	var title string
	if m := titleRe.FindStringSubmatch(htmlContent); len(m) > 1 {
		title = m[1]
	}

	content, err := htmltomarkdown.ConvertString(htmlContent)
	if err != nil {
		return tool.NewTextErrorResponse(
			fmt.Sprintf("html to markdown conversion failed: %v", err),
		), nil
	}

	type result struct {
		URL     string `json:"url"`
		Title   string `json:"title"`
		Content string `json:"content"`
	}

	return tool.NewJSONResponse(result{
		URL:     input.URL,
		Title:   title,
		Content: content,
	}), nil
}
