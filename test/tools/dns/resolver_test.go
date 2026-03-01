package dns

import (
	"testing"

	mdns "codeberg.org/miekg/dns"
	"github.com/joakimcarlsson/squeeze/internal/tools/dns"
)

func TestSubdomains(t *testing.T) {
	subs := dns.Subdomains()
	if len(subs) == 0 {
		t.Fatal("wordlist is empty")
	}

	for _, s := range subs {
		if s == "" {
			t.Error("wordlist contains empty entry")
		}
	}

	expected := []string{"www", "mail", "api", "admin", "vpn"}
	for _, want := range expected {
		found := false
		for _, s := range subs {
			if s == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected subdomain %q not found in wordlist", want)
		}
	}
}

func TestParseQType(t *testing.T) {
	tests := []struct {
		input string
		want  uint16
		ok    bool
	}{
		{"A", mdns.TypeA, true},
		{"a", mdns.TypeA, true},
		{"AAAA", mdns.TypeAAAA, true},
		{"aaaa", mdns.TypeAAAA, true},
		{"MX", mdns.TypeMX, true},
		{"TXT", mdns.TypeTXT, true},
		{"CNAME", mdns.TypeCNAME, true},
		{"NS", mdns.TypeNS, true},
		{"SOA", mdns.TypeSOA, true},
		{"PTR", mdns.TypePTR, true},
		{"SRV", mdns.TypeSRV, true},
		{"AXFR", mdns.TypeAXFR, true},
		{" mx ", mdns.TypeMX, true},
		{"INVALID", 0, false},
		{"", 0, false},
		{"HINFO", 0, false},
	}

	for _, tt := range tests {
		got, ok := dns.ParseQType(tt.input)
		if ok != tt.ok {
			t.Errorf("ParseQType(%q): got ok=%v, want ok=%v", tt.input, ok, tt.ok)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseQType(%q): got %d, want %d", tt.input, got, tt.want)
		}
	}
}
