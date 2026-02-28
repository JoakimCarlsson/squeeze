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

func TestFetchWebpage_Info(t *testing.T) {
	f := sqtools.NewFetch()
	info := f.Info()
	if info.Name != "fetch_webpage" {
		t.Fatalf("expected name fetch_webpage, got %s", info.Name)
	}
}

func TestFetchWebpage_EmptyURL(t *testing.T) {
	f := sqtools.NewFetch()
	resp, err := f.Run(
		context.Background(),
		makeCall("fetch_webpage", `{"url":""}`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected error for empty URL")
	}
}

func TestFetchWebpage_BasicHTML(t *testing.T) {
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(
				w,
				`<html><head><title>Test Page</title></head><body><h1>Hello</h1><p>World</p></body></html>`,
			)
		}),
	)
	defer srv.Close()

	f := sqtools.NewFetch()
	input := fmt.Sprintf(`{"url":"%s"}`, srv.URL)
	resp, err := f.Run(
		context.Background(),
		tool.ToolCall{ID: "t1", Name: "fetch_webpage", Input: input},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}

	var result struct {
		URL     string `json:"url"`
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if result.Title != "Test Page" {
		t.Errorf("expected title 'Test Page', got %q", result.Title)
	}
	if result.URL != srv.URL {
		t.Errorf("expected URL %q, got %q", srv.URL, result.URL)
	}
	if !strings.Contains(result.Content, "Hello") {
		t.Errorf("expected content to contain 'Hello', got %q", result.Content)
	}
	if !strings.Contains(result.Content, "World") {
		t.Errorf("expected content to contain 'World', got %q", result.Content)
	}
}

func TestFetchWebpage_Non200(t *testing.T) {
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}),
	)
	defer srv.Close()

	f := sqtools.NewFetch()
	input := fmt.Sprintf(`{"url":"%s"}`, srv.URL)
	resp, err := f.Run(
		context.Background(),
		tool.ToolCall{ID: "t1", Name: "fetch_webpage", Input: input},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected error for 404 response")
	}
	if !strings.Contains(resp.Content, "404") {
		t.Errorf("expected 404 in error, got %q", resp.Content)
	}
}

func TestFetchWebpage_StripsScriptTags(t *testing.T) {
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(
				w,
				`<html><body><script>alert('xss')</script><p>safe content</p></body></html>`,
			)
		}),
	)
	defer srv.Close()

	f := sqtools.NewFetch()
	input := fmt.Sprintf(`{"url":"%s"}`, srv.URL)
	resp, err := f.Run(
		context.Background(),
		tool.ToolCall{ID: "t1", Name: "fetch_webpage", Input: input},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if strings.Contains(result.Content, "alert") {
		t.Error("expected script content to be stripped from markdown output")
	}
	if !strings.Contains(result.Content, "safe content") {
		t.Error("expected 'safe content' to be preserved")
	}
}

func TestFetchWebpage_PreservesLinks(t *testing.T) {
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(
				w,
				`<html><body><a href="https://example.com">Example</a></body></html>`,
			)
		}),
	)
	defer srv.Close()

	f := sqtools.NewFetch()
	input := fmt.Sprintf(`{"url":"%s"}`, srv.URL)
	resp, err := f.Run(
		context.Background(),
		tool.ToolCall{ID: "t1", Name: "fetch_webpage", Input: input},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if !strings.Contains(result.Content, "https://example.com") {
		t.Errorf("expected link URL to be preserved, got %q", result.Content)
	}
	if !strings.Contains(result.Content, "Example") {
		t.Errorf("expected link text to be preserved, got %q", result.Content)
	}
}
