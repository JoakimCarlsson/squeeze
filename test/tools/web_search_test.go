package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/joakimcarlsson/ai/tool"
	sqtools "github.com/joakimcarlsson/squeeze/internal/tools"
)

const fakeSearchHTML = `<html><body>
<div class="result results_links results_links_deep web-result ">
  <h2 class="result__title">
    <a class="result__a" href="https://example.com/one">First Result</a>
  </h2>
  <a class="result__snippet" href="https://example.com/one">This is the first snippet</a>
</div>
<div class="result results_links results_links_deep web-result ">
  <h2 class="result__title">
    <a class="result__a" href="https://example.com/two">Second Result</a>
  </h2>
  <a class="result__snippet" href="https://example.com/two">This is the second snippet</a>
</div>
<div class="result results_links results_links_deep web-result ">
  <h2 class="result__title">
    <a class="result__a" href="https://example.com/three">Third Result</a>
  </h2>
  <a class="result__snippet" href="https://example.com/three">This is the third snippet</a>
</div>
</body></html>`

func fakeSearchServer(html string) *httptest.Server {
	return httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, html)
		}),
	)
}

func TestWebSearch_Info(t *testing.T) {
	s := sqtools.NewWebSearch()
	info := s.Info()
	if info.Name != "web_search" {
		t.Fatalf("expected name web_search, got %s", info.Name)
	}
}

func TestWebSearch_EmptyQuery(t *testing.T) {
	s := sqtools.NewWebSearch()
	resp, err := s.Run(
		context.Background(),
		makeCall("web_search", `{"query":""}`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected error for empty query")
	}
}

func TestWebSearch_LiveQuery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live DDG query in short mode")
	}

	s := sqtools.NewWebSearch()
	resp, err := s.Run(context.Background(), tool.ToolCall{
		ID:    "t1",
		Name:  "web_search",
		Input: `{"query":"golang programming language","limit":3}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}

	var results []struct {
		Title   string `json:"title"`
		URL     string `json:"url"`
		Snippet string `json:"snippet"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &results); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	if len(results) > 3 {
		t.Errorf("expected at most 3 results, got %d", len(results))
	}

	for i, r := range results {
		if r.Title == "" {
			t.Errorf("result %d: empty title", i)
		}
		if r.URL == "" {
			t.Errorf("result %d: empty URL", i)
		}
	}
}

func TestWebSearch_ParsesResults(t *testing.T) {
	srv := fakeSearchServer(fakeSearchHTML)
	defer srv.Close()

	s := sqtools.NewWebSearchWithEndpoints("", srv.URL)
	resp, err := s.Run(context.Background(), tool.ToolCall{
		ID:    "t1",
		Name:  "web_search",
		Input: `{"query":"test","limit":5}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}

	var results []struct {
		Title   string `json:"title"`
		URL     string `json:"url"`
		Snippet string `json:"snippet"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &results); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if results[0].Title != "First Result" {
		t.Errorf("expected title 'First Result', got %q", results[0].Title)
	}
	if results[0].URL != "https://example.com/one" {
		t.Errorf(
			"expected URL 'https://example.com/one', got %q",
			results[0].URL,
		)
	}
	if results[0].Snippet != "This is the first snippet" {
		t.Errorf(
			"expected snippet 'This is the first snippet', got %q",
			results[0].Snippet,
		)
	}
}

func TestWebSearch_LimitResults(t *testing.T) {
	srv := fakeSearchServer(fakeSearchHTML)
	defer srv.Close()

	s := sqtools.NewWebSearchWithEndpoints("", srv.URL)
	resp, err := s.Run(context.Background(), tool.ToolCall{
		ID:    "t1",
		Name:  "web_search",
		Input: `{"query":"test","limit":2}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var results []struct {
		Title string `json:"title"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &results); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestWebSearch_NoResults(t *testing.T) {
	srv := fakeSearchServer(
		`<html><body><div class="no-results">No results</div></body></html>`,
	)
	defer srv.Close()

	s := sqtools.NewWebSearchWithEndpoints("", srv.URL)
	resp, err := s.Run(context.Background(), tool.ToolCall{
		ID:    "t1",
		Name:  "web_search",
		Input: `{"query":"asdfghjklqwertyuiop","limit":5}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("no results should not be an error: %s", resp.Content)
	}
	if !strings.Contains(resp.Content, "No results") {
		t.Errorf("expected 'No results' message, got %q", resp.Content)
	}
}

func TestWebSearch_HTMLEntities(t *testing.T) {
	htmlWithEntities := `<html><body>
<div class="result results_links results_links_deep web-result ">
  <h2 class="result__title">
    <a class="result__a" href="https://example.com/a&amp;b=1">Title &amp; More</a>
  </h2>
  <a class="result__snippet" href="#">Snippet with &lt;special&gt; chars</a>
</div>
</body></html>`

	srv := fakeSearchServer(htmlWithEntities)
	defer srv.Close()

	s := sqtools.NewWebSearchWithEndpoints("", srv.URL)
	resp, err := s.Run(context.Background(), tool.ToolCall{
		ID:    "t1",
		Name:  "web_search",
		Input: `{"query":"test","limit":5}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var results []struct {
		Title   string `json:"title"`
		URL     string `json:"url"`
		Snippet string `json:"snippet"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &results); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Title != "Title & More" {
		t.Errorf("expected unescaped title, got %q", results[0].Title)
	}
	if results[0].URL != "https://example.com/a&b=1" {
		t.Errorf("expected unescaped URL, got %q", results[0].URL)
	}
	if !strings.Contains(results[0].Snippet, "<special>") {
		t.Errorf("expected unescaped snippet, got %q", results[0].Snippet)
	}
}

func TestWebSearch_SkipsAds(t *testing.T) {
	htmlWithAds := `<html><body>
<div class="result results_links results_links_deep result--ad ">
  <h2 class="result__title">
    <a class="result__a" href="https://ad.example.com">Buy Stuff</a>
  </h2>
  <a class="result__snippet" href="#">Ad snippet</a>
</div>
<div class="result results_links results_links_deep web-result ">
  <h2 class="result__title">
    <a class="result__a" href="https://real.example.com">Real Result</a>
  </h2>
  <a class="result__snippet" href="#">Real snippet</a>
</div>
</body></html>`

	srv := fakeSearchServer(htmlWithAds)
	defer srv.Close()

	s := sqtools.NewWebSearchWithEndpoints("", srv.URL)
	resp, err := s.Run(context.Background(), tool.ToolCall{
		ID:    "t1",
		Name:  "web_search",
		Input: `{"query":"test","limit":5}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var results []struct {
		Title string `json:"title"`
		URL   string `json:"url"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &results); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result (ad skipped), got %d", len(results))
	}
	if results[0].Title != "Real Result" {
		t.Errorf("expected 'Real Result', got %q", results[0].Title)
	}
}
