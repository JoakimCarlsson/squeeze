package tools

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/joakimcarlsson/ai/agent"
	"github.com/joakimcarlsson/ai/tool"
)

type SSLInfoParams struct {
	Host               string `json:"host"                          desc:"Hostname or IP address to connect to"`
	Port               int    `json:"port,omitempty"                desc:"Port to connect on (default: 443)"`
	CheckWeakProtocols bool   `json:"check_weak_protocols,omitempty" desc:"Probe for weak protocol support: TLS 1.0 and TLS 1.1"`
}

type sslCertInfo struct {
	Subject      string   `json:"subject"`
	SAN          []string `json:"san"`
	Issuer       string   `json:"issuer"`
	ValidFrom    string   `json:"valid_from"`
	ValidUntil   string   `json:"valid_until"`
	SerialNumber string   `json:"serial_number"`
	SelfSigned   bool     `json:"self_signed"`
	Expired      bool     `json:"expired"`
}

type sslInfoResult struct {
	Host          string      `json:"host"`
	Port          int         `json:"port"`
	TLSVersion    string      `json:"tls_version"`
	CipherSuite   string      `json:"cipher_suite"`
	Certificate   sslCertInfo `json:"certificate"`
	WeakProtocols []string    `json:"weak_protocols,omitempty"`
}

type SSLInfoTool struct{}

func NewSSLInfo() *SSLInfoTool {
	return &SSLInfoTool{}
}

func (t *SSLInfoTool) Info() tool.ToolInfo {
	return tool.NewToolInfo(
		"ssl_info",
		`Connect to a host and retrieve TLS certificate and configuration details.
Extracts the subject, SANs (Subject Alternative Names), issuer, validity dates, and serial number from the leaf certificate.
SANs frequently expose additional subdomains and internal hostnames not visible in DNS enumeration, making this useful for attack surface mapping.
Reports the negotiated TLS version (TLS 1.0/1.1 are findings) and cipher suite.
Detects self-signed and expired certificates.
Optionally probes whether the server accepts TLS 1.0 or TLS 1.1 connections.`,
		SSLInfoParams{},
	)
}

func (t *SSLInfoTool) Run(ctx context.Context, params tool.ToolCall) (tool.ToolResponse, error) {
	input, err := agent.ParseToolInput[SSLInfoParams](params.Input)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid input: %v", err)), nil
	}

	if input.Host == "" {
		return tool.NewTextErrorResponse("host is required"), nil
	}

	port := input.Port
	if port == 0 {
		port = 443
	}

	addr := fmt.Sprintf("%s:%d", input.Host, port)

	connCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	dialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         input.Host,
		},
	}

	conn, err := dialer.DialContext(connCtx, "tcp", addr)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("failed to connect to %s: %v", addr, err)), nil
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return tool.NewTextErrorResponse("unexpected connection type"), nil
	}

	state := tlsConn.ConnectionState()
	certs := state.PeerCertificates

	if len(certs) == 0 {
		return tool.NewTextErrorResponse("no certificates returned by server"), nil
	}

	result := sslInfoResult{
		Host:        input.Host,
		Port:        port,
		TLSVersion:  tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		Certificate: buildCertInfo(certs[0]),
	}

	if input.CheckWeakProtocols {
		result.WeakProtocols = probeWeakProtocols(ctx, addr, input.Host)
	}

	return tool.NewJSONResponse(result), nil
}

func buildCertInfo(cert *x509.Certificate) sslCertInfo {
	sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	return sslCertInfo{
		Subject:      cert.Subject.String(),
		SAN:          sans,
		Issuer:       cert.Issuer.String(),
		ValidFrom:    cert.NotBefore.UTC().Format("2006-01-02"),
		ValidUntil:   cert.NotAfter.UTC().Format("2006-01-02"),
		SerialNumber: formatSerial(cert.SerialNumber),
		SelfSigned:   bytes.Equal(cert.RawIssuer, cert.RawSubject),
		Expired:      time.Now().After(cert.NotAfter),
	}
}

func probeWeakProtocols(ctx context.Context, addr, serverName string) []string {
	probes := []struct {
		name    string
		version uint16
	}{
		{"TLS 1.1", tls.VersionTLS11},
		{"TLS 1.0", tls.VersionTLS10},
	}

	var weak []string
	for _, p := range probes {
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{},
			Config: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         serverName,
				MinVersion:         p.version,
				MaxVersion:         p.version,
			},
		}
		conn, err := dialer.DialContext(probeCtx, "tcp", addr)
		cancel()
		if err == nil {
			conn.Close()
			weak = append(weak, p.name)
		}
	}

	return weak
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}

func formatSerial(n *big.Int) string {
	if n == nil {
		return ""
	}
	b := n.Bytes()
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, ":")
}
