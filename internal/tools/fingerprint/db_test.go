package fingerprint

import (
	"net/http"
	"testing"
)

func TestDefault_Singleton(t *testing.T) {
	a := Default()
	b := Default()
	if a != b {
		t.Fatal("Default() must return the same instance")
	}
}

func TestNew_LoadsTechnologies(t *testing.T) {
	db := New()
	if len(db.entries) == 0 {
		t.Fatal("expected non-empty entries after load")
	}
}

func makeHeaders(pairs ...string) http.Header {
	h := make(http.Header)
	for i := 0; i+1 < len(pairs); i += 2 {
		h.Set(pairs[i], pairs[i+1])
	}
	return h
}

func findHit(hits []Hit, name string) *Hit {
	for i := range hits {
		if hits[i].Name == name {
			return &hits[i]
		}
	}
	return nil
}

func TestMatch_NginxViaHeader(t *testing.T) {
	db := New()
	hdrs := makeHeaders("Server", "nginx/1.24.0")
	hits := db.Match("http://example.com", hdrs, nil, nil)
	if findHit(hits, "Nginx") == nil {
		t.Error("expected Nginx to be detected via Server header")
	}
}

func TestMatch_PHPViaHeader(t *testing.T) {
	db := New()
	hdrs := makeHeaders("X-Powered-By", "PHP/8.2.0")
	hits := db.Match("http://example.com", hdrs, nil, nil)
	if findHit(hits, "PHP") == nil {
		t.Error("expected PHP to be detected via X-Powered-By header")
	}
}

func TestMatch_WordPressViaBody(t *testing.T) {
	db := New()
	body := []byte(`<html><head><link rel="stylesheet" href="/wp-content/themes/test/style.css"></head><body></body></html>`)
	hits := db.Match("http://example.com", nil, nil, body)
	if findHit(hits, "WordPress") == nil {
		t.Error("expected WordPress to be detected via body")
	}
}

func TestMatch_jQueryViaScriptSrc(t *testing.T) {
	db := New()
	body := []byte(`<html><body><script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script></body></html>`)
	hits := db.Match("http://example.com", nil, nil, body)
	if findHit(hits, "jQuery") == nil {
		t.Error("expected jQuery to be detected via script src")
	}
}

func TestMatch_CloudflareViaHeader(t *testing.T) {
	db := New()
	hdrs := makeHeaders("Server", "cloudflare", "CF-Ray", "abc123-LHR")
	hits := db.Match("http://example.com", hdrs, nil, nil)
	if findHit(hits, "Cloudflare") == nil {
		t.Error("expected Cloudflare to be detected")
	}
}

func TestMatch_WAFCategory(t *testing.T) {
	db := New()
	hdrs := makeHeaders("Server", "DataDome")
	hits := db.Match("http://example.com", hdrs, nil, nil)
	dd := findHit(hits, "DataDome")
	if dd == nil {
		t.Fatal("expected DataDome to be detected")
	}
	foundWAF := false
	for _, cat := range dd.Categories {
		if cat == 16 {
			foundWAF = true
			break
		}
	}
	if !foundWAF {
		t.Errorf("expected DataDome to have WAF category 16, got %v", dd.Categories)
	}
}

func TestMatch_NginxVersion(t *testing.T) {
	db := New()
	hdrs := makeHeaders("Server", "nginx/1.24.0")
	hits := db.Match("http://example.com", hdrs, nil, nil)
	h := findHit(hits, "Nginx")
	if h == nil {
		t.Fatal("expected Nginx to be detected")
	}
	if h.Version != "1.24.0" {
		t.Errorf("expected version 1.24.0, got %q", h.Version)
	}
}

func TestMatch_NoDuplicates(t *testing.T) {
	db := New()
	hdrs := makeHeaders("Server", "nginx/1.24.0")
	hits := db.Match("http://example.com", hdrs, nil, nil)
	seen := make(map[string]int)
	for _, h := range hits {
		seen[h.Name]++
	}
	for name, count := range seen {
		if count > 1 {
			t.Errorf("technology %q appeared %d times, expected 1", name, count)
		}
	}
}

func TestMatch_EmptyResponse(t *testing.T) {
	db := New()
	hits := db.Match("http://example.com", nil, nil, nil)
	if len(hits) != 0 {
		t.Errorf("expected no hits on empty response, got %v", hits)
	}
}

func TestMatch_CookieDetection(t *testing.T) {
	db := New()
	cookies := []*http.Cookie{{Name: "PHPSESSID", Value: "abc123"}}
	hits := db.Match("http://example.com", nil, cookies, nil)
	if findHit(hits, "PHP") == nil {
		t.Error("expected PHP to be detected via PHPSESSID cookie")
	}
}
