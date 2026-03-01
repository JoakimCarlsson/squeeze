package dns

import (
	"bufio"
	"context"
	"embed"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	mdns "codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

//go:embed wordlists/subdomains.txt
var wordlistFS embed.FS

var (
	subdomainsOnce sync.Once
	subdomainsList []string
)

type Record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`

	Priority uint16 `json:"priority,omitempty"`

	MX string `json:"mx,omitempty"`

	NS   string `json:"ns,omitempty"`
	Mbox string `json:"mbox,omitempty"`

	Serial  uint32 `json:"serial,omitempty"`
	Refresh uint32 `json:"refresh,omitempty"`
	Retry   uint32 `json:"retry,omitempty"`
	Expire  uint32 `json:"expire,omitempty"`
	MinTTL  uint32 `json:"min_ttl,omitempty"`

	Target string `json:"target,omitempty"`
	Port   uint16 `json:"port,omitempty"`
	Weight uint16 `json:"weight,omitempty"`
}

const DefaultResolver = "8.8.8.8:53"

func Subdomains() []string {
	subdomainsOnce.Do(func() {
		f, err := wordlistFS.Open("wordlists/subdomains.txt")
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" {
				subdomainsList = append(subdomainsList, line)
			}
		}
	})
	return subdomainsList
}

func Resolve(ctx context.Context, host string, qtype uint16, resolver string) ([]Record, error) {
	client := mdns.NewClient()
	msg := mdns.NewMsg(host, qtype)
	if msg == nil {
		return nil, fmt.Errorf("unsupported record type %d", qtype)
	}

	resp, _, err := client.Exchange(ctx, msg, "udp", resolver)
	if err != nil {
		return nil, fmt.Errorf("dns query failed: %w", err)
	}

	var records []Record
	for _, rr := range resp.Answer {
		records = append(records, rrToRecord(rr))
	}
	return records, nil
}

func ReverseLookup(ctx context.Context, ip string, resolver string) ([]Record, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("invalid IP for reverse lookup: %w", err)
	}
	arpa := dnsutil.ReverseAddr(addr)
	return Resolve(ctx, arpa, mdns.TypePTR, resolver)
}

func AttemptAXFR(ctx context.Context, domain string, resolver string) ([]Record, error) {
	nsRecords, err := Resolve(ctx, domain, mdns.TypeNS, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve NS records: %w", err)
	}

	if len(nsRecords) == 0 {
		return nil, fmt.Errorf("no NS records found for %s", domain)
	}

	client := mdns.NewClient()
	msg := mdns.NewMsg(domain, mdns.TypeAXFR)
	if msg == nil {
		return nil, fmt.Errorf("failed to create AXFR message")
	}

	var lastErr error
	for _, ns := range nsRecords {
		nsHost := strings.TrimSuffix(ns.Value, ".")

		nsAddr := net.JoinHostPort(nsHost, "53")

		env, err := client.TransferIn(ctx, msg, "tcp", nsAddr)
		if err != nil {
			lastErr = err
			continue
		}

		var records []Record
		for envelope := range env {
			if envelope.Error != nil {
				lastErr = envelope.Error
				break
			}
			for _, rr := range envelope.Answer {
				records = append(records, rrToRecord(rr))
			}
		}
		if len(records) > 0 {
			return records, nil
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("zone transfer failed: %w", lastErr)
	}
	return nil, fmt.Errorf("zone transfer returned no records")
}

func EnumerateSubdomains(ctx context.Context, domain string, resolver string) ([]string, error) {
	subs := Subdomains()
	if len(subs) == 0 {
		return nil, fmt.Errorf("empty subdomain wordlist")
	}

	type result struct {
		subdomain string
	}

	const workers = 10
	work := make(chan string, workers)
	results := make(chan result, workers)
	var wg sync.WaitGroup

	for range workers {
		wg.Go(func() {
			client := mdns.NewClient()
			for sub := range work {
				if ctx.Err() != nil {
					return
				}
				fqdn := sub + "." + domain
				msg := mdns.NewMsg(fqdn, mdns.TypeA)
				if msg == nil {
					continue
				}
				resp, _, err := client.Exchange(ctx, msg, "udp", resolver)
				if err != nil {
					continue
				}
				if len(resp.Answer) > 0 {
					results <- result{subdomain: fqdn}
				}
			}
		})
	}

	go func() {
		for _, sub := range subs {
			if ctx.Err() != nil {
				break
			}
			work <- sub
		}
		close(work)
		wg.Wait()
		close(results)
	}()

	var found []string
	for r := range results {
		found = append(found, r.subdomain)
	}
	return found, nil
}

func ParseQType(s string) (uint16, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "A":
		return mdns.TypeA, true
	case "AAAA":
		return mdns.TypeAAAA, true
	case "MX":
		return mdns.TypeMX, true
	case "TXT":
		return mdns.TypeTXT, true
	case "CNAME":
		return mdns.TypeCNAME, true
	case "NS":
		return mdns.TypeNS, true
	case "SOA":
		return mdns.TypeSOA, true
	case "PTR":
		return mdns.TypePTR, true
	case "SRV":
		return mdns.TypeSRV, true
	case "AXFR":
		return mdns.TypeAXFR, true
	default:
		return 0, false
	}
}

func rrToRecord(rr mdns.RR) Record {
	hdr := rr.Header()
	rec := Record{
		Name:  hdr.Name,
		TTL:   hdr.TTL,
		Value: rr.Data().String(),
	}

	switch v := rr.(type) {
	case *mdns.A:
		rec.Type = "A"
		rec.Value = v.Addr.String()
	case *mdns.AAAA:
		rec.Type = "AAAA"
		rec.Value = v.Addr.String()
	case *mdns.MX:
		rec.Type = "MX"
		rec.Priority = v.Preference
		rec.MX = v.Mx
		rec.Value = v.Mx
	case *mdns.TXT:
		rec.Type = "TXT"
		rec.Value = strings.Join(v.Txt, " ")
	case *mdns.CNAME:
		rec.Type = "CNAME"
		rec.Value = v.Target
	case *mdns.NS:
		rec.Type = "NS"
		rec.NS = v.Ns
		rec.Value = v.Ns
	case *mdns.SOA:
		rec.Type = "SOA"
		rec.NS = v.Ns
		rec.Mbox = v.Mbox
		rec.Serial = v.Serial
		rec.Refresh = v.Refresh
		rec.Retry = v.Retry
		rec.Expire = v.Expire
		rec.MinTTL = v.Minttl
		rec.Value = fmt.Sprintf("%s %s %d %d %d %d %d", v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	case *mdns.PTR:
		rec.Type = "PTR"
		rec.Value = v.Ptr
	case *mdns.SRV:
		rec.Type = "SRV"
		rec.Priority = v.Priority
		rec.Weight = v.Weight
		rec.Port = v.Port
		rec.Target = v.Target
		rec.Value = fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target)
	default:
		t := mdns.RRToType(rr)
		rec.Type = mdns.TypeToString[t]
		if rec.Type == "" {
			rec.Type = fmt.Sprintf("TYPE%d", t)
		}
	}

	return rec
}
