package tools

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"os/exec"
	"testing"

	sqtools "github.com/joakimcarlsson/squeeze/internal/tools"
)

func TestPortScan_Info(t *testing.T) {
	s := sqtools.NewPortScan()
	info := s.Info()
	if info.Name != "port_scan" {
		t.Fatalf("expected name port_scan, got %s", info.Name)
	}
}

func TestPortScan_EmptyTarget(t *testing.T) {
	s := sqtools.NewPortScan()
	resp, err := s.Run(
		context.Background(),
		makeCall("port_scan", `{"target":""}`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected error for empty target")
	}
}

func TestPortScan_InvalidTarget(t *testing.T) {
	s := sqtools.NewPortScan()
	for _, target := range []string{"foo bar", "10.0.0.1;echo", "--script vuln"} {
		input, _ := json.Marshal(map[string]string{"target": target})
		resp, err := s.Run(
			context.Background(),
			makeCall("port_scan", string(input)),
		)
		if err != nil {
			t.Fatalf("unexpected error for target %q: %v", target, err)
		}
		if !resp.IsError {
			t.Errorf("expected error for invalid target %q", target)
		}
	}
}

func TestParseNmapXML_BasicOpen(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	var result struct {
		XMLName xml.Name `xml:"nmaprun"`
		Hosts   []struct {
			Status struct {
				State string `xml:"state,attr"`
			} `xml:"status"`
			Addresses []struct {
				Addr     string `xml:"addr,attr"`
				AddrType string `xml:"addrtype,attr"`
			} `xml:"address"`
			Ports []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   int    `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name string `xml:"name,attr"`
				} `xml:"service"`
			} `xml:"ports>port"`
		} `xml:"host"`
	}

	if err := xml.Unmarshal([]byte(xmlData), &result); err != nil {
		t.Fatalf("failed to parse XML: %v", err)
	}

	if len(result.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(result.Hosts))
	}

	host := result.Hosts[0]
	if host.Status.State != "up" {
		t.Errorf("expected host state up, got %q", host.Status.State)
	}
	if len(host.Addresses) != 1 || host.Addresses[0].Addr != "93.184.216.34" {
		t.Errorf("unexpected address: %+v", host.Addresses)
	}
	if len(host.Ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(host.Ports))
	}
	if host.Ports[0].PortID != 80 || host.Ports[0].State.State != "open" || host.Ports[0].Service.Name != "http" {
		t.Errorf("unexpected port 0: %+v", host.Ports[0])
	}
	if host.Ports[1].PortID != 443 || host.Ports[1].Service.Name != "https" {
		t.Errorf("unexpected port 1: %+v", host.Ports[1])
	}
}

func TestParseNmapXML_ServiceDetection(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu 3ubuntu0.10">
          <cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24.0">
          <cpe>cpe:/a:nginx:nginx:1.24.0</cpe>
        </service>
      </port>
    </ports>
  </host>
</nmaprun>`

	var result struct {
		XMLName xml.Name `xml:"nmaprun"`
		Hosts   []struct {
			Ports []struct {
				PortID  int `xml:"portid,attr"`
				Service struct {
					Name    string   `xml:"name,attr"`
					Product string   `xml:"product,attr"`
					Version string   `xml:"version,attr"`
					Extra   string   `xml:"extrainfo,attr"`
					CPEs    []string `xml:"cpe"`
				} `xml:"service"`
			} `xml:"ports>port"`
		} `xml:"host"`
	}

	if err := xml.Unmarshal([]byte(xmlData), &result); err != nil {
		t.Fatalf("failed to parse XML: %v", err)
	}

	ports := result.Hosts[0].Ports
	if len(ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(ports))
	}

	ssh := ports[0]
	if ssh.Service.Product != "OpenSSH" || ssh.Service.Version != "8.9p1" || ssh.Service.Extra != "Ubuntu 3ubuntu0.10" {
		t.Errorf("unexpected SSH service: %+v", ssh.Service)
	}
	if len(ssh.Service.CPEs) != 1 || ssh.Service.CPEs[0] != "cpe:/a:openbsd:openssh:8.9p1" {
		t.Errorf("unexpected SSH CPEs: %v", ssh.Service.CPEs)
	}

	nginx := ports[1]
	if nginx.Service.Product != "nginx" || nginx.Service.Version != "1.24.0" {
		t.Errorf("unexpected nginx service: %+v", nginx.Service)
	}
}

func TestParseNmapXML_HostDown(t *testing.T) {
	xmlData := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="down"/>
    <address addr="192.168.1.99" addrtype="ipv4"/>
  </host>
</nmaprun>`

	var result struct {
		XMLName xml.Name `xml:"nmaprun"`
		Hosts   []struct {
			Status struct {
				State string `xml:"state,attr"`
			} `xml:"status"`
			Ports []struct{} `xml:"ports>port"`
		} `xml:"host"`
	}

	if err := xml.Unmarshal([]byte(xmlData), &result); err != nil {
		t.Fatalf("failed to parse XML: %v", err)
	}
	if result.Hosts[0].Status.State != "down" {
		t.Errorf("expected host state down, got %q", result.Hosts[0].Status.State)
	}
	if len(result.Hosts[0].Ports) != 0 {
		t.Errorf("expected no ports for down host, got %d", len(result.Hosts[0].Ports))
	}
}

func TestPortScan_Integration(t *testing.T) {
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("nmap not installed, skipping integration test")
	}

	s := sqtools.NewPortScan()
	resp, err := s.Run(
		context.Background(),
		makeCall("port_scan", `{"target":"127.0.0.1","ports":"1","timeout_seconds":10}`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}

	var result struct {
		Host  string `json:"host"`
		State string `json:"state"`
		Ports []struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			State    string `json:"state"`
		} `json:"ports"`
		Command string `json:"command"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Host == "" {
		t.Error("expected non-empty host")
	}
	if result.State == "" {
		t.Error("expected non-empty state")
	}
	if result.Command == "" {
		t.Error("expected non-empty command")
	}
}
