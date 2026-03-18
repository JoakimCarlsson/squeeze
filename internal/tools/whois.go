package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/joakimcarlsson/ai/agent"
	"github.com/joakimcarlsson/ai/tool"
)

const (
	rdapBootstrapDNSURL = "https://data.iana.org/rdap/dns.json"
	rdapARINBaseURL     = "https://rdap.arin.net/registry/ip/"
	maxWhoisBody        = 1 << 20
	whoisTimeout        = 15 * time.Second
)

type WhoisParams struct {
	Target string `json:"target" desc:"Domain name or IP address to look up"`
}

type domainWhoisResult struct {
	Target      string   `json:"target"`
	Type        string   `json:"type"`
	Registrar   string   `json:"registrar,omitempty"`
	Org         string   `json:"org,omitempty"`
	Created     string   `json:"created,omitempty"`
	Expires     string   `json:"expires,omitempty"`
	NameServers []string `json:"name_servers,omitempty"`
}

type ipWhoisResult struct {
	Target       string `json:"target"`
	Type         string `json:"type"`
	ASN          string `json:"asn,omitempty"`
	Org          string `json:"org,omitempty"`
	Country      string `json:"country,omitempty"`
	CIDR         string `json:"cidr,omitempty"`
	AbuseContact string `json:"abuse_contact,omitempty"`
}

type rdapBootstrapResp struct {
	Services [][][]string `json:"services"`
}

type rdapDomainResp struct {
	LdhName     string       `json:"ldhName"`
	Nameservers []rdapNS     `json:"nameservers"`
	Events      []rdapEvent  `json:"events"`
	Entities    []rdapEntity `json:"entities"`
}

type rdapNS struct {
	LdhName string `json:"ldhName"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapEntity struct {
	Roles      []string     `json:"roles"`
	VCardArray []any        `json:"vcardArray"`
	Entities   []rdapEntity `json:"entities"`
}

type rdapIPResp struct {
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	Country      string       `json:"country"`
	Name         string       `json:"name"`
	CIDRs        []rdapCIDR   `json:"cidr0_cidrs"`
	Entities     []rdapEntity `json:"entities"`
}

type rdapCIDR struct {
	V4Prefix string `json:"v4prefix"`
	V6Prefix string `json:"v6prefix"`
	Length   int    `json:"length"`
}

type WhoisTool struct {
	client       *http.Client
	bootstrapURL string
	arinURL      string
}

func NewWhois() *WhoisTool {
	return &WhoisTool{
		client:       &http.Client{Timeout: whoisTimeout},
		bootstrapURL: rdapBootstrapDNSURL,
		arinURL:      rdapARINBaseURL,
	}
}

func NewWhoisWithURLs(bootstrapURL, arinURL string) *WhoisTool {
	return &WhoisTool{
		client:       &http.Client{Timeout: whoisTimeout},
		bootstrapURL: bootstrapURL,
		arinURL:      arinURL,
	}
}

func (t *WhoisTool) Info() tool.ToolInfo {
	return tool.NewToolInfo(
		"whois",
		`Perform WHOIS/RDAP lookups for domains and IP addresses.
For domains: returns registrar, org, registration/expiry dates, and name servers.
For IPs: returns ASN, org, country, IP range (CIDR), and abuse contact.
Uses RDAP (RESTful WHOIS) which returns structured JSON natively.
Accepts any domain name (e.g. example.com) or IPv4/IPv6 address.`,
		WhoisParams{},
	)
}

func (t *WhoisTool) Run(ctx context.Context, params tool.ToolCall) (tool.ToolResponse, error) {
	input, err := agent.ParseToolInput[WhoisParams](params.Input)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid input: %v", err)), nil
	}

	if input.Target == "" {
		return tool.NewTextErrorResponse("target is required"), nil
	}

	target := strings.TrimSpace(input.Target)

	if net.ParseIP(target) != nil {
		result, err := t.lookupIP(ctx, target)
		if err != nil {
			return tool.NewTextErrorResponse(fmt.Sprintf("IP WHOIS failed: %v", err)), nil
		}
		return tool.NewJSONResponse(result), nil
	}

	result, err := t.lookupDomain(ctx, strings.ToLower(target))
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("domain WHOIS failed: %v", err)), nil
	}
	return tool.NewJSONResponse(result), nil
}

func (t *WhoisTool) lookupDomain(ctx context.Context, domain string) (*domainWhoisResult, error) {
	server, err := t.rdapServerForDomain(ctx, domain)
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(server, "/") + "/domain/" + domain
	data, err := t.fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetching RDAP: %w", err)
	}

	var resp rdapDomainResp
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parsing RDAP response: %w", err)
	}

	result := &domainWhoisResult{
		Target: domain,
		Type:   "domain",
	}

	for _, ns := range resp.Nameservers {
		if ns.LdhName != "" {
			result.NameServers = append(result.NameServers, strings.ToLower(ns.LdhName))
		}
	}

	for _, ev := range resp.Events {
		switch ev.Action {
		case "registration":
			result.Created = parseRDAPDate(ev.Date)
		case "expiration":
			result.Expires = parseRDAPDate(ev.Date)
		}
	}

	for _, e := range resp.Entities {
		for _, role := range e.Roles {
			if role == "registrar" && result.Registrar == "" {
				result.Registrar = vcardField(e.VCardArray, "fn")
			}
			if role == "registrant" && result.Org == "" {
				result.Org = vcardField(e.VCardArray, "fn")
				if result.Org == "" {
					result.Org = vcardField(e.VCardArray, "org")
				}
			}
		}
		for _, nested := range e.Entities {
			for _, role := range nested.Roles {
				if role == "registrant" && result.Org == "" {
					result.Org = vcardField(nested.VCardArray, "fn")
				}
			}
		}
	}

	return result, nil
}

func (t *WhoisTool) rdapServerForDomain(ctx context.Context, domain string) (string, error) {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid domain: %s", domain)
	}
	tld := parts[len(parts)-1]

	data, err := t.fetch(ctx, t.bootstrapURL)
	if err != nil {
		return "", fmt.Errorf("fetching RDAP bootstrap: %w", err)
	}

	var bootstrap rdapBootstrapResp
	if err := json.Unmarshal(data, &bootstrap); err != nil {
		return "", fmt.Errorf("parsing RDAP bootstrap: %w", err)
	}

	for _, svc := range bootstrap.Services {
		if len(svc) < 2 {
			continue
		}
		for _, entry := range svc[0] {
			if strings.EqualFold(entry, tld) && len(svc[1]) > 0 {
				return svc[1][0], nil
			}
		}
	}

	return "", fmt.Errorf("no RDAP server found for TLD: .%s", tld)
}

func (t *WhoisTool) lookupIP(ctx context.Context, ip string) (*ipWhoisResult, error) {
	data, err := t.fetch(ctx, t.arinURL+ip)
	if err != nil {
		return nil, fmt.Errorf("fetching RDAP: %w", err)
	}

	var resp rdapIPResp
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parsing RDAP response: %w", err)
	}

	result := &ipWhoisResult{
		Target:  ip,
		Type:    "ip",
		Country: resp.Country,
		CIDR:    extractCIDR(resp),
	}

	for _, e := range resp.Entities {
		for _, role := range e.Roles {
			if role == "registrant" && result.Org == "" {
				result.Org = vcardField(e.VCardArray, "fn")
				if result.Org == "" {
					result.Org = vcardField(e.VCardArray, "org")
				}
			}
			if role == "abuse" && result.AbuseContact == "" {
				result.AbuseContact = vcardField(e.VCardArray, "email")
			}
		}
		for _, nested := range e.Entities {
			for _, role := range nested.Roles {
				if role == "abuse" && result.AbuseContact == "" {
					result.AbuseContact = vcardField(nested.VCardArray, "email")
				}
				if role == "registrant" && result.Org == "" {
					result.Org = vcardField(nested.VCardArray, "fn")
				}
			}
		}
	}

	if asn, err := cymruASN(ctx, ip); err == nil {
		result.ASN = asn
	}

	return result, nil
}

func (t *WhoisTool) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxWhoisBody))
}

func cymruASN(ctx context.Context, ip string) (string, error) {
	host := ip + ".origin.asn.cymru.com"
	if strings.Contains(ip, ":") {
		expanded, err := reverseIPv6Nibbles(ip)
		if err != nil {
			return "", err
		}
		host = expanded + ".origin6.asn.cymru.com"
	}

	txts, err := net.DefaultResolver.LookupTXT(ctx, host)
	if err != nil {
		return "", err
	}

	for _, txt := range txts {
		parts := strings.SplitN(txt, "|", 2)
		if len(parts) >= 1 {
			asn := strings.TrimSpace(parts[0])
			if asn != "" {
				return "AS" + asn, nil
			}
		}
	}
	return "", fmt.Errorf("no ASN in TXT response")
}

func reverseIPv6Nibbles(ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("invalid IPv6: %s", ip)
	}
	parsed = parsed.To16()

	nibbles := make([]string, 0, 32)
	for _, b := range parsed {
		nibbles = append(nibbles, fmt.Sprintf("%x", b>>4))
		nibbles = append(nibbles, fmt.Sprintf("%x", b&0xf))
	}

	for i, j := 0, len(nibbles)-1; i < j; i, j = i+1, j-1 {
		nibbles[i], nibbles[j] = nibbles[j], nibbles[i]
	}

	return strings.Join(nibbles, "."), nil
}

func extractCIDR(resp rdapIPResp) string {
	if len(resp.CIDRs) > 0 {
		c := resp.CIDRs[0]
		prefix := c.V4Prefix
		if prefix == "" {
			prefix = c.V6Prefix
		}
		if prefix != "" {
			return fmt.Sprintf("%s/%d", prefix, c.Length)
		}
	}
	return ""
}

func vcardField(vcardArr []any, field string) string {
	if len(vcardArr) < 2 {
		return ""
	}
	entries, ok := vcardArr[1].([]any)
	if !ok {
		return ""
	}
	for _, entry := range entries {
		e, ok := entry.([]any)
		if !ok || len(e) < 4 {
			continue
		}
		name, ok := e[0].(string)
		if !ok || !strings.EqualFold(name, field) {
			continue
		}
		if val, ok := e[3].(string); ok {
			return val
		}
	}
	return ""
}

func parseRDAPDate(s string) string {
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.000Z",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format("2006-01-02")
		}
	}
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}
