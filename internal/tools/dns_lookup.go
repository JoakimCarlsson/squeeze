package tools

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/joakimcarlsson/ai/agent"
	"github.com/joakimcarlsson/ai/tool"
	"github.com/joakimcarlsson/squeeze/internal/tools/dns"
)

var dnsHostPattern = regexp.MustCompile(`^[a-zA-Z0-9._:\-]+$`)

type DNSLookupParams struct {
	Host          string `json:"host"                      desc:"Target hostname or IP address (IP for PTR lookups)"`
	RecordType    string `json:"record_type,omitempty"     desc:"DNS record type: A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, or AXFR (default: A)"`
	SubdomainEnum bool   `json:"subdomain_enum,omitempty"  desc:"Enumerate subdomains using built-in wordlist"`
	Resolver      string `json:"resolver,omitempty"        desc:"Custom DNS resolver (e.g. 8.8.8.8:53). Defaults to 8.8.8.8:53"`
	Timeout       int    `json:"timeout_seconds,omitempty" desc:"Max duration in seconds (default: 30, max: 120)"`
}

type dnsLookupResult struct {
	Host       string       `json:"host"`
	RecordType string       `json:"record_type"`
	Resolver   string       `json:"resolver"`
	Records    []dns.Record `json:"records"`
	Subdomains []string     `json:"subdomains,omitempty"`
}

type DNSLookupTool struct{}

func NewDNSLookup() *DNSLookupTool {
	return &DNSLookupTool{}
}

func (t *DNSLookupTool) Info() tool.ToolInfo {
	return tool.NewToolInfo(
		"dns_lookup",
		"Perform DNS lookups against a target host and return structured results. "+
			"Supports record types: A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, AXFR. "+
			"Can enumerate subdomains using a built-in wordlist. "+
			"Returns per-record type, TTL, value, and type-specific fields (priority, SOA serial/refresh/retry/expire, SRV port/weight). "+
			"Use PTR with an IP address for reverse DNS lookups. "+
			"Use AXFR to attempt a zone transfer. "+
			"Defaults to A record lookup with 8.8.8.8:53 resolver.",
		DNSLookupParams{},
	)
}

func (t *DNSLookupTool) Run(ctx context.Context, params tool.ToolCall) (tool.ToolResponse, error) {
	input, err := agent.ParseToolInput[DNSLookupParams](params.Input)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid input: %v", err)), nil
	}

	if input.Host == "" {
		return tool.NewTextErrorResponse("host is required"), nil
	}
	if !dnsHostPattern.MatchString(input.Host) {
		return tool.NewTextErrorResponse("invalid host: must be a hostname or IP address"), nil
	}

	recordType := "A"
	if input.RecordType != "" {
		recordType = strings.ToUpper(strings.TrimSpace(input.RecordType))
	}

	if recordType != "AXFR" {
		if _, ok := dns.ParseQType(recordType); !ok {
			return tool.NewTextErrorResponse(fmt.Sprintf("unsupported record type: %s", recordType)), nil
		}
	}

	resolver := dns.DefaultResolver
	if input.Resolver != "" {
		resolver = input.Resolver
		if !strings.Contains(resolver, ":") {
			resolver = resolver + ":53"
		}
	}

	timeout := 30 * time.Second
	if input.Timeout > 0 {
		t := min(input.Timeout, 120)
		timeout = time.Duration(t) * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result := dnsLookupResult{
		Host:       input.Host,
		RecordType: recordType,
		Resolver:   resolver,
	}

	if recordType == "AXFR" {
		records, err := dns.AttemptAXFR(ctx, input.Host, resolver)
		if err != nil {
			return tool.NewTextErrorResponse(fmt.Sprintf("zone transfer failed: %v", err)), nil
		}
		result.Records = records
	} else if recordType == "PTR" {
		records, err := dns.ReverseLookup(ctx, input.Host, resolver)
		if err != nil {
			return tool.NewTextErrorResponse(fmt.Sprintf("reverse lookup failed: %v", err)), nil
		}
		result.Records = records
	} else {
		qtype, _ := dns.ParseQType(recordType)
		records, err := dns.Resolve(ctx, input.Host, qtype, resolver)
		if err != nil {
			return tool.NewTextErrorResponse(fmt.Sprintf("dns lookup failed: %v", err)), nil
		}
		result.Records = records
	}

	if input.SubdomainEnum {
		subs, err := dns.EnumerateSubdomains(ctx, input.Host, resolver)
		if err != nil {
			return tool.NewTextErrorResponse(fmt.Sprintf("subdomain enumeration failed: %v", err)), nil
		}
		result.Subdomains = subs
	}

	return tool.NewJSONResponse(result), nil
}
