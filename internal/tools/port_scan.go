package tools

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/joakimcarlsson/ai/agent"
	"github.com/joakimcarlsson/ai/tool"
)

var targetPattern = regexp.MustCompile(`^[a-zA-Z0-9._:\-]+$`)

type PortScanParams struct {
	Target      string `json:"target"                   desc:"Target host — IP address or hostname"`
	Ports       string `json:"ports,omitempty"           desc:"Port spec: comma-separated (22,80,443), range (1-1024), or topN (top100). Omit for nmap defaults."`
	ServiceScan bool   `json:"service_scan,omitempty"    desc:"Enable service/version detection (-sV). Slower but returns service and version info."`
	Timeout     int    `json:"timeout_seconds,omitempty" desc:"Max scan duration in seconds (default: 120, max: 600)"`
}

type portScanResult struct {
	Host    string       `json:"host"`
	State   string       `json:"state"`
	Ports   []portResult `json:"ports"`
	Command string       `json:"command"`
}

type portResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Version  string `json:"version,omitempty"`
	CPE      string `json:"cpe,omitempty"`
}

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Ports     []nmapPort    `xml:"ports>port"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string   `xml:"name,attr"`
	Product string   `xml:"product,attr"`
	Version string   `xml:"version,attr"`
	Extra   string   `xml:"extrainfo,attr"`
	CPEs    []string `xml:"cpe"`
}

type PortScanTool struct{}

func NewPortScan() *PortScanTool {
	return &PortScanTool{}
}

func (t *PortScanTool) Info() tool.ToolInfo {
	return tool.NewToolInfo(
		"port_scan",
		`Run an nmap port scan against a target host and return structured results.
Returns per-port state, service name, version, and CPE.
Defaults to TCP connect scan (-sT). Enable service_scan for version detection (-sV).
Supports custom port ranges, comma-separated ports, or topN (e.g. top100).
Requires nmap installed on the host.`,
		PortScanParams{},
	)
}

func (t *PortScanTool) Run(ctx context.Context, params tool.ToolCall) (tool.ToolResponse, error) {
	input, err := agent.ParseToolInput[PortScanParams](params.Input)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid input: %v", err)), nil
	}

	if input.Target == "" {
		return tool.NewTextErrorResponse("target is required"), nil
	}
	if !targetPattern.MatchString(input.Target) {
		return tool.NewTextErrorResponse("invalid target: must be a hostname or IP address"), nil
	}

	nmapPath, err := exec.LookPath("nmap")
	if err != nil {
		return tool.NewTextErrorResponse("nmap is not installed or not in PATH. Install with: apt install nmap / brew install nmap"), nil
	}

	args := []string{"-sT", "-oX", "-", "--noninteractive"}

	if input.ServiceScan {
		args = append(args, "-sV")
	}

	if input.Ports != "" {
		if n := parseTopN(input.Ports); n > 0 {
			args = append(args, "--top-ports", strconv.Itoa(n))
		} else {
			args = append(args, "-p", input.Ports)
		}
	}

	args = append(args, input.Target)

	timeout := 120 * time.Second
	if input.Timeout > 0 {
		t := min(input.Timeout, 600)
		timeout = time.Duration(t) * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, nmapPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if runErr != nil {
		if ctx.Err() != nil {
			return tool.NewTextErrorResponse(fmt.Sprintf("scan timed out after %d seconds", int(timeout.Seconds()))), nil
		}
		if stdout.Len() == 0 {
			return tool.NewTextErrorResponse(fmt.Sprintf("nmap failed: %s", stderr.String())), nil
		}
	}

	var nmapResult nmapRun
	if err := xml.Unmarshal(stdout.Bytes(), &nmapResult); err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("failed to parse nmap XML output: %v", err)), nil
	}

	if len(nmapResult.Hosts) == 0 {
		return tool.NewTextErrorResponse("no hosts found in scan results"), nil
	}

	host := nmapResult.Hosts[0]

	addr := input.Target
	for _, a := range host.Addresses {
		if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
			addr = a.Addr
			break
		}
	}

	hostState := "unknown"
	if host.Status.State != "" {
		hostState = host.Status.State
	}

	ports := make([]portResult, 0, len(host.Ports))
	for _, p := range host.Ports {
		pr := portResult{
			Port:     p.PortID,
			Protocol: p.Protocol,
			State:    p.State.State,
			Service:  p.Service.Name,
			Version:  buildVersionString(p.Service.Product, p.Service.Version, p.Service.Extra),
		}
		if len(p.Service.CPEs) > 0 {
			pr.CPE = p.Service.CPEs[0]
		}
		ports = append(ports, pr)
	}

	cmdStr := strings.Join(append([]string{nmapPath}, args...), " ")

	return tool.NewJSONResponse(portScanResult{
		Host:    addr,
		State:   hostState,
		Ports:   ports,
		Command: cmdStr,
	}), nil
}

func parseTopN(ports string) int {
	s := strings.ToLower(strings.TrimSpace(ports))
	if !strings.HasPrefix(s, "top") {
		return 0
	}
	n, err := strconv.Atoi(s[3:])
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

func buildVersionString(product, version, extra string) string {
	parts := make([]string, 0, 3)
	if product != "" {
		parts = append(parts, product)
	}
	if version != "" {
		parts = append(parts, version)
	}
	if extra != "" {
		parts = append(parts, extra)
	}
	return strings.Join(parts, " ")
}
