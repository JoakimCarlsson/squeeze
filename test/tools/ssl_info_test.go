package tools

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	sqtools "github.com/joakimcarlsson/squeeze/internal/tools"
)

type sslResult struct {
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	TLSVersion    string   `json:"tls_version"`
	CipherSuite   string   `json:"cipher_suite"`
	Certificate   sslCert  `json:"certificate"`
	WeakProtocols []string `json:"weak_protocols"`
}

type sslCert struct {
	Subject      string   `json:"subject"`
	SAN          []string `json:"san"`
	Issuer       string   `json:"issuer"`
	ValidFrom    string   `json:"valid_from"`
	ValidUntil   string   `json:"valid_until"`
	SerialNumber string   `json:"serial_number"`
	SelfSigned   bool     `json:"self_signed"`
	Expired      bool     `json:"expired"`
}

func runSSLInfo(t *testing.T, input string) sslResult {
	t.Helper()
	s := sqtools.NewSSLInfo()
	resp, err := s.Run(context.Background(), makeCall("ssl_info", input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}
	var result sslResult
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	return result
}

func runSSLInfoError(t *testing.T, input string) string {
	t.Helper()
	s := sqtools.NewSSLInfo()
	resp, err := s.Run(context.Background(), makeCall("ssl_info", input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatalf("expected tool error, got success: %s", resp.Content)
	}
	return resp.Content
}

func tlsTestAddr(t *testing.T, srv *httptest.Server) (host, port string) {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}
	h, p, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("failed to split host:port from %q: %v", u.Host, err)
	}
	return h, p
}

func generateSelfSignedCert(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to create TLS keypair: %v", err)
	}
	return cert
}

func newCustomTLSListener(t *testing.T, cfg *tls.Config) (host, port string) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
			}(conn)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	return h, p
}

func newExpiredCertServer(t *testing.T) (host, port string) {
	t.Helper()
	now := time.Now()
	cert := generateSelfSignedCert(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	return newCustomTLSListener(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
}

func newWeakProtocolServer(t *testing.T, minVer, maxVer uint16) (host, port string) {
	t.Helper()
	now := time.Now()
	cert := generateSelfSignedCert(t, now.Add(-time.Hour), now.Add(24*time.Hour))
	return newCustomTLSListener(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVer,
		MaxVersion:   maxVer,
	})
}

func TestSSLInfo_Info(t *testing.T) {
	s := sqtools.NewSSLInfo()
	info := s.Info()
	if info.Name != "ssl_info" {
		t.Fatalf("expected name ssl_info, got %q", info.Name)
	}
}

func TestSSLInfo_MissingHost(t *testing.T) {
	errMsg := runSSLInfoError(t, `{"host":""}`)
	if !strings.Contains(errMsg, "host is required") {
		t.Errorf("expected 'host is required', got %q", errMsg)
	}
}

func TestSSLInfo_BasicFields(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host, portStr := tlsTestAddr(t, srv)
	port, _ := strconv.Atoi(portStr)

	result := runSSLInfo(t, fmt.Sprintf(`{"host":%q,"port":%d}`, host, port))

	if result.Host != host {
		t.Errorf("expected host %q, got %q", host, result.Host)
	}
	if result.Port != port {
		t.Errorf("expected port %d, got %d", port, result.Port)
	}
	if result.TLSVersion == "" {
		t.Error("expected non-empty tls_version")
	}
	if result.CipherSuite == "" {
		t.Error("expected non-empty cipher_suite")
	}
}

func TestSSLInfo_TLSVersionFormat(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	host, portStr := tlsTestAddr(t, srv)
	port, _ := strconv.Atoi(portStr)

	result := runSSLInfo(t, fmt.Sprintf(`{"host":%q,"port":%d}`, host, port))

	if !strings.HasPrefix(result.TLSVersion, "TLS ") {
		t.Errorf("expected tls_version to start with 'TLS ', got %q", result.TLSVersion)
	}
}

func TestSSLInfo_SANs(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	host, portStr := tlsTestAddr(t, srv)
	port, _ := strconv.Atoi(portStr)

	result := runSSLInfo(t, fmt.Sprintf(`{"host":%q,"port":%d}`, host, port))

	if len(result.Certificate.SAN) == 0 {
		t.Fatal("expected at least one SAN, got none")
	}
	found := false
	for _, san := range result.Certificate.SAN {
		if strings.Contains(san, "127.0.0.1") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected SAN list to contain '127.0.0.1', got %v", result.Certificate.SAN)
	}
}

func TestSSLInfo_SelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	host, portStr := tlsTestAddr(t, srv)
	port, _ := strconv.Atoi(portStr)

	result := runSSLInfo(t, fmt.Sprintf(`{"host":%q,"port":%d}`, host, port))

	if !result.Certificate.SelfSigned {
		t.Error("expected self_signed to be true for httptest server")
	}
}

func TestSSLInfo_NotExpired(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	host, portStr := tlsTestAddr(t, srv)
	port, _ := strconv.Atoi(portStr)

	result := runSSLInfo(t, fmt.Sprintf(`{"host":%q,"port":%d}`, host, port))

	if result.Certificate.Expired {
		t.Error("expected expired to be false for a fresh httptest certificate")
	}
}

func TestSSLInfo_ValidityDates(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	host, portStr := tlsTestAddr(t, srv)
	port, _ := strconv.Atoi(portStr)

	result := runSSLInfo(t, fmt.Sprintf(`{"host":%q,"port":%d}`, host, port))

	datePattern := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	if !datePattern.MatchString(result.Certificate.ValidFrom) {
		t.Errorf("expected valid_from in YYYY-MM-DD format, got %q", result.Certificate.ValidFrom)
	}
	if !datePattern.MatchString(result.Certificate.ValidUntil) {
		t.Errorf("expected valid_until in YYYY-MM-DD format, got %q", result.Certificate.ValidUntil)
	}
}

func TestSSLInfo_SerialNumber(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	host, portStr := tlsTestAddr(t, srv)
	port, _ := strconv.Atoi(portStr)

	result := runSSLInfo(t, fmt.Sprintf(`{"host":%q,"port":%d}`, host, port))

	if result.Certificate.SerialNumber == "" {
		t.Error("expected non-empty serial_number")
	}
}

func TestSSLInfo_CertSubjectAndIssuer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	host, portStr := tlsTestAddr(t, srv)
	port, _ := strconv.Atoi(portStr)

	result := runSSLInfo(t, fmt.Sprintf(`{"host":%q,"port":%d}`, host, port))

	if result.Certificate.Subject == "" {
		t.Error("expected non-empty subject")
	}
	if result.Certificate.Issuer == "" {
		t.Error("expected non-empty issuer")
	}
}

func TestSSLInfo_ExpiredCert(t *testing.T) {
	host, portStr := newExpiredCertServer(t)
	port, _ := strconv.Atoi(portStr)

	result := runSSLInfo(t, fmt.Sprintf(`{"host":%q,"port":%d}`, host, port))

	if !result.Certificate.Expired {
		t.Error("expected expired to be true for a cert with NotAfter in the past")
	}
}

func TestSSLInfo_WeakProtocols_Empty(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	host, portStr := tlsTestAddr(t, srv)
	port, _ := strconv.Atoi(portStr)

	result := runSSLInfo(t, fmt.Sprintf(`{"host":%q,"port":%d,"check_weak_protocols":true}`, host, port))

	for _, p := range result.WeakProtocols {
		if p == "TLS 1.0" || p == "TLS 1.1" {
			t.Errorf("did not expect %q reported as supported by a default httptest server (Go 1.22+ minimum is TLS 1.2)", p)
		}
	}
}

func TestSSLInfo_WeakProtocols_Detected(t *testing.T) {
	host, portStr := newWeakProtocolServer(t, tls.VersionTLS10, 0)
	port, _ := strconv.Atoi(portStr)

	result := runSSLInfo(t, fmt.Sprintf(`{"host":%q,"port":%d,"check_weak_protocols":true}`, host, port))

	found := false
	for _, p := range result.WeakProtocols {
		if p == "TLS 1.0" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'TLS 1.0' in weak_protocols, got %v", result.WeakProtocols)
	}
}

func TestSSLInfo_NoWeakProtocolsWithoutFlag(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	host, portStr := tlsTestAddr(t, srv)
	port, _ := strconv.Atoi(portStr)

	s := sqtools.NewSSLInfo()
	resp, err := s.Run(context.Background(), makeCall("ssl_info", fmt.Sprintf(`{"host":%q,"port":%d}`, host, port)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(resp.Content), &raw); err != nil {
		t.Fatalf("failed to parse raw response: %v", err)
	}
	if _, ok := raw["weak_protocols"]; ok {
		t.Error("expected weak_protocols to be absent from JSON when check_weak_protocols is false")
	}
}
