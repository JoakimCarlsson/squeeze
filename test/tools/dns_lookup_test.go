package tools

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/joakimcarlsson/squeeze/internal/tools/dns"

	sqtools "github.com/joakimcarlsson/squeeze/internal/tools"
)

func TestDNSLookup_Info(t *testing.T) {
	d := sqtools.NewDNSLookup()
	info := d.Info()
	if info.Name != "dns_lookup" {
		t.Fatalf("expected name dns_lookup, got %s", info.Name)
	}
}

func TestDNSLookup_EmptyHost(t *testing.T) {
	d := sqtools.NewDNSLookup()
	resp, err := d.Run(context.Background(), makeCall("dns_lookup", `{"host":""}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected error for empty host")
	}
}

func TestDNSLookup_InvalidHost(t *testing.T) {
	d := sqtools.NewDNSLookup()
	for _, host := range []string{"foo bar", "test;echo", "bad>host"} {
		input, _ := json.Marshal(map[string]string{"host": host})
		resp, err := d.Run(context.Background(), makeCall("dns_lookup", string(input)))
		if err != nil {
			t.Fatalf("unexpected error for host %q: %v", host, err)
		}
		if !resp.IsError {
			t.Errorf("expected error for invalid host %q", host)
		}
	}
}

func TestDNSLookup_InvalidRecordType(t *testing.T) {
	d := sqtools.NewDNSLookup()
	resp, err := d.Run(context.Background(), makeCall("dns_lookup", `{"host":"example.com","record_type":"INVALID"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected error for invalid record type")
	}
}

func TestDNSLookup_InvalidJSON(t *testing.T) {
	d := sqtools.NewDNSLookup()
	resp, err := d.Run(context.Background(), makeCall("dns_lookup", `{bad json}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestDNSLookup_DefaultsToA(t *testing.T) {
	d := sqtools.NewDNSLookup()
	resp, err := d.Run(context.Background(), makeCall("dns_lookup", `{"host":"example.com"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}

	var result struct {
		RecordType string       `json:"record_type"`
		Records    []dns.Record `json:"records"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.RecordType != "A" {
		t.Errorf("expected record_type A, got %s", result.RecordType)
	}
	if len(result.Records) == 0 {
		t.Error("expected at least one A record for example.com")
	}
}

func TestDNSLookup_ResolverNormalization(t *testing.T) {
	d := sqtools.NewDNSLookup()
	resp, err := d.Run(context.Background(), makeCall("dns_lookup", `{"host":"example.com","resolver":"1.1.1.1"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}

	var result struct {
		Resolver string `json:"resolver"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Resolver != "1.1.1.1:53" {
		t.Errorf("expected resolver 1.1.1.1:53, got %s", result.Resolver)
	}
}

func TestDNSLookup_MX(t *testing.T) {
	d := sqtools.NewDNSLookup()
	resp, err := d.Run(context.Background(), makeCall("dns_lookup", `{"host":"google.com","record_type":"MX"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}

	var result struct {
		Records []dns.Record `json:"records"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(result.Records) == 0 {
		t.Error("expected at least one MX record for google.com")
	}
	for _, rec := range result.Records {
		if rec.Type != "MX" {
			t.Errorf("expected MX record, got %s", rec.Type)
		}
	}
}

func TestDNSLookup_NS(t *testing.T) {
	d := sqtools.NewDNSLookup()
	resp, err := d.Run(context.Background(), makeCall("dns_lookup", `{"host":"google.com","record_type":"NS"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}

	var result struct {
		Records []dns.Record `json:"records"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(result.Records) == 0 {
		t.Error("expected at least one NS record for google.com")
	}
	for _, rec := range result.Records {
		if rec.Type != "NS" {
			t.Errorf("expected NS record, got %s", rec.Type)
		}
	}
}
