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
)

type domainWhoisResult struct {
	Target      string   `json:"target"`
	Type        string   `json:"type"`
	Registrar   string   `json:"registrar"`
	Org         string   `json:"org"`
	Created     string   `json:"created"`
	Expires     string   `json:"expires"`
	NameServers []string `json:"name_servers"`
}

type ipWhoisResult struct {
	Target       string `json:"target"`
	Type         string `json:"type"`
	ASN          string `json:"asn"`
	Org          string `json:"org"`
	Country      string `json:"country"`
	CIDR         string `json:"cidr"`
	AbuseContact string `json:"abuse_contact"`
}

func newWhoisWithServers(t *testing.T, bootstrapHandler, rdapHandler http.HandlerFunc) *sqtools.WhoisTool {
	t.Helper()
	bootstrap := httptest.NewServer(bootstrapHandler)
	rdap := httptest.NewServer(rdapHandler)
	t.Cleanup(func() {
		bootstrap.Close()
		rdap.Close()
	})
	return sqtools.NewWhoisWithURLs(bootstrap.URL, rdap.URL+"/")
}

func bootstrapFor(tld, rdapURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := fmt.Sprintf(`{"services":[[[ %q],[%q]]]}`, tld, rdapURL+"/")
		fmt.Fprint(w, resp)
	}
}

func runWhoisDomain(t *testing.T, tool *sqtools.WhoisTool, target string) domainWhoisResult {
	t.Helper()
	resp, err := tool.Run(context.Background(), makeCall("whois", fmt.Sprintf(`{"target":%q}`, target)))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}
	var result domainWhoisResult
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	return result
}

func runWhoisIP(t *testing.T, tool *sqtools.WhoisTool, target string) ipWhoisResult {
	t.Helper()
	resp, err := tool.Run(context.Background(), makeCall("whois", fmt.Sprintf(`{"target":%q}`, target)))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}
	var result ipWhoisResult
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	return result
}

func runWhoisError(t *testing.T, tool *sqtools.WhoisTool, target string) string {
	t.Helper()
	resp, err := tool.Run(context.Background(), makeCall("whois", fmt.Sprintf(`{"target":%q}`, target)))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !resp.IsError {
		t.Fatalf("expected tool error for target %q, got: %s", target, resp.Content)
	}
	return resp.Content
}

const fakeDomainRDAP = `{
  "objectClassName": "domain",
  "ldhName": "EXAMPLE.COM",
  "nameservers": [
    {"ldhName": "NS1.EXAMPLE.COM"},
    {"ldhName": "NS2.EXAMPLE.COM"}
  ],
  "events": [
    {"eventAction": "registration", "eventDate": "2000-01-15T12:00:00Z"},
    {"eventAction": "expiration",   "eventDate": "2030-06-20T00:00:00Z"},
    {"eventAction": "last changed", "eventDate": "2023-01-01T00:00:00Z"}
  ],
  "entities": [
    {
      "roles": ["registrar"],
      "vcardArray": ["vcard", [
        ["version", {}, "text", "4.0"],
        ["fn",      {}, "text", "Example Registrar Inc."]
      ]]
    },
    {
      "roles": ["registrant"],
      "vcardArray": ["vcard", [
        ["fn", {}, "text", "Example Corp"]
      ]]
    }
  ]
}`

const fakeIPRDAP = `{
  "objectClassName": "ip network",
  "startAddress": "93.184.216.0",
  "endAddress":   "93.184.216.255",
  "country": "US",
  "cidr0_cidrs": [{"v4prefix": "93.184.216.0", "length": 24}],
  "entities": [
    {
      "roles": ["registrant"],
      "vcardArray": ["vcard", [
        ["fn", {}, "text", "Edgecast Inc."]
      ]],
      "entities": [
        {
          "roles": ["abuse"],
          "vcardArray": ["vcard", [
            ["fn",    {}, "text", "Abuse Contact"],
            ["email", {}, "text", "abuse@edgecast.com"]
          ]]
        }
      ]
    }
  ]
}`

func TestWhois_Info(t *testing.T) {
	w := sqtools.NewWhois()
	if w.Info().Name != "whois" {
		t.Fatalf("expected name 'whois', got %q", w.Info().Name)
	}
}

func TestWhois_EmptyTarget(t *testing.T) {
	w := sqtools.NewWhois()
	resp, err := w.Run(context.Background(), makeCall("whois", `{"target":""}`))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected tool error for empty target")
	}
	if !strings.Contains(resp.Content, "target is required") {
		t.Errorf("expected 'target is required' in error, got: %s", resp.Content)
	}
}

func TestWhois_InvalidJSON(t *testing.T) {
	w := sqtools.NewWhois()
	resp, err := w.Run(context.Background(), makeCall("whois", `not json`))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected tool error for malformed JSON input")
	}
}

func TestWhois_Domain_Registrar(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeDomainRDAP)
	}))
	defer rdapSrv.Close()

	bootstrapSrv := httptest.NewServer(bootstrapFor("com", rdapSrv.URL))
	defer bootstrapSrv.Close()

	tool := sqtools.NewWhoisWithURLs(bootstrapSrv.URL, rdapSrv.URL+"/")
	result := runWhoisDomain(t, tool, "example.com")

	if result.Registrar != "Example Registrar Inc." {
		t.Errorf("expected registrar 'Example Registrar Inc.', got %q", result.Registrar)
	}
}

func TestWhois_Domain_Org(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeDomainRDAP)
	}))
	defer rdapSrv.Close()

	bootstrapSrv := httptest.NewServer(bootstrapFor("com", rdapSrv.URL))
	defer bootstrapSrv.Close()

	tool := sqtools.NewWhoisWithURLs(bootstrapSrv.URL, rdapSrv.URL+"/")
	result := runWhoisDomain(t, tool, "example.com")

	if result.Org != "Example Corp" {
		t.Errorf("expected org 'Example Corp', got %q", result.Org)
	}
}

func TestWhois_Domain_NameServers(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeDomainRDAP)
	}))
	defer rdapSrv.Close()

	bootstrapSrv := httptest.NewServer(bootstrapFor("com", rdapSrv.URL))
	defer bootstrapSrv.Close()

	tool := sqtools.NewWhoisWithURLs(bootstrapSrv.URL, rdapSrv.URL+"/")
	result := runWhoisDomain(t, tool, "example.com")

	if len(result.NameServers) != 2 {
		t.Fatalf("expected 2 nameservers, got %d", len(result.NameServers))
	}
	for _, ns := range result.NameServers {
		if ns != strings.ToLower(ns) {
			t.Errorf("nameserver %q not lowercase", ns)
		}
	}
	if result.NameServers[0] != "ns1.example.com" {
		t.Errorf("expected 'ns1.example.com', got %q", result.NameServers[0])
	}
}

func TestWhois_Domain_Dates(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeDomainRDAP)
	}))
	defer rdapSrv.Close()

	bootstrapSrv := httptest.NewServer(bootstrapFor("com", rdapSrv.URL))
	defer bootstrapSrv.Close()

	tool := sqtools.NewWhoisWithURLs(bootstrapSrv.URL, rdapSrv.URL+"/")
	result := runWhoisDomain(t, tool, "example.com")

	if result.Created != "2000-01-15" {
		t.Errorf("expected created '2000-01-15', got %q", result.Created)
	}
	if result.Expires != "2030-06-20" {
		t.Errorf("expected expires '2030-06-20', got %q", result.Expires)
	}
}

func TestWhois_Domain_TypeField(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeDomainRDAP)
	}))
	defer rdapSrv.Close()

	bootstrapSrv := httptest.NewServer(bootstrapFor("com", rdapSrv.URL))
	defer bootstrapSrv.Close()

	tool := sqtools.NewWhoisWithURLs(bootstrapSrv.URL, rdapSrv.URL+"/")
	result := runWhoisDomain(t, tool, "example.com")

	if result.Type != "domain" {
		t.Errorf("expected type 'domain', got %q", result.Type)
	}
	if result.Target != "example.com" {
		t.Errorf("expected target 'example.com', got %q", result.Target)
	}
}

func TestWhois_Domain_UnknownTLD(t *testing.T) {
	bootstrapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"services":[]}`)
	}))
	defer bootstrapSrv.Close()

	tool := sqtools.NewWhoisWithURLs(bootstrapSrv.URL, "http://unused/")
	runWhoisError(t, tool, "example.unknowntld")
}

func TestWhois_IP_Org(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeIPRDAP)
	}))
	defer rdapSrv.Close()

	tool := sqtools.NewWhoisWithURLs("http://unused/", rdapSrv.URL+"/")
	result := runWhoisIP(t, tool, "93.184.216.34")

	if result.Org != "Edgecast Inc." {
		t.Errorf("expected org 'Edgecast Inc.', got %q", result.Org)
	}
}

func TestWhois_IP_Country(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeIPRDAP)
	}))
	defer rdapSrv.Close()

	tool := sqtools.NewWhoisWithURLs("http://unused/", rdapSrv.URL+"/")
	result := runWhoisIP(t, tool, "93.184.216.34")

	if result.Country != "US" {
		t.Errorf("expected country 'US', got %q", result.Country)
	}
}

func TestWhois_IP_CIDR(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeIPRDAP)
	}))
	defer rdapSrv.Close()

	tool := sqtools.NewWhoisWithURLs("http://unused/", rdapSrv.URL+"/")
	result := runWhoisIP(t, tool, "93.184.216.34")

	if result.CIDR != "93.184.216.0/24" {
		t.Errorf("expected CIDR '93.184.216.0/24', got %q", result.CIDR)
	}
}

func TestWhois_IP_AbuseContact(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeIPRDAP)
	}))
	defer rdapSrv.Close()

	tool := sqtools.NewWhoisWithURLs("http://unused/", rdapSrv.URL+"/")
	result := runWhoisIP(t, tool, "93.184.216.34")

	if result.AbuseContact != "abuse@edgecast.com" {
		t.Errorf("expected abuse contact 'abuse@edgecast.com', got %q", result.AbuseContact)
	}
}

func TestWhois_IP_TypeField(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fakeIPRDAP)
	}))
	defer rdapSrv.Close()

	tool := sqtools.NewWhoisWithURLs("http://unused/", rdapSrv.URL+"/")
	result := runWhoisIP(t, tool, "93.184.216.34")

	if result.Type != "ip" {
		t.Errorf("expected type 'ip', got %q", result.Type)
	}
	if result.Target != "93.184.216.34" {
		t.Errorf("expected target '93.184.216.34', got %q", result.Target)
	}
}

func TestWhois_IP_CIDR_FallbackEmpty(t *testing.T) {
	const noCIDR = `{
		"objectClassName": "ip network",
		"startAddress": "10.0.0.0",
		"endAddress":   "10.0.0.255",
		"country": "AU",
		"entities": []
	}`

	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, noCIDR)
	}))
	defer rdapSrv.Close()

	tool := sqtools.NewWhoisWithURLs("http://unused/", rdapSrv.URL+"/")
	result := runWhoisIP(t, tool, "10.0.0.1")

	if result.CIDR != "" {
		t.Errorf("expected empty CIDR, got %q", result.CIDR)
	}
}

func TestWhois_Domain_Live(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live WHOIS query")
	}

	w := sqtools.NewWhois()
	resp, err := w.Run(context.Background(), makeCall("whois", `{"target":"example.com"}`))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("tool error: %s", resp.Content)
	}

	var result domainWhoisResult
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Type != "domain" {
		t.Errorf("expected type 'domain', got %q", result.Type)
	}
	if len(result.NameServers) == 0 {
		t.Error("expected at least one nameserver")
	}
}

func TestWhois_IP_Live(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live WHOIS query")
	}

	w := sqtools.NewWhois()
	resp, err := w.Run(context.Background(), makeCall("whois", `{"target":"93.184.216.34"}`))
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("tool error: %s", resp.Content)
	}

	var result ipWhoisResult
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Type != "ip" {
		t.Errorf("expected type 'ip', got %q", result.Type)
	}
	if result.Country == "" {
		t.Error("expected non-empty country")
	}
}
