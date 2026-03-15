package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/joakimcarlsson/ai/agent"
	"github.com/joakimcarlsson/ai/tool"
)

type runScriptParams struct {
	Path           string `json:"path"                      desc:"Path to the Python script inside the container"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" desc:"Execution timeout in seconds (default 30, max 300)"`
	Args           string `json:"args,omitempty"            desc:"Command-line arguments to pass to the script"`
}

type RunScriptTool struct {
	mgr *Manager
}

func (t *RunScriptTool) Info() tool.ToolInfo {
	return tool.NewToolInfo(
		"docker_run_python",
		`Execute a Python script inside the Docker container and return stdout, stderr, exit code, and duration.
The container has internet access and pre-installed packages: requests, httpx, aiohttp, pwntools, impacket, cryptography, pyjwt, scapy, paramiko, beautifulsoup4, lxml.
Use this for batch HTTP probing, exploit scripts, data processing, and any multi-step automation that would be inefficient as individual tool calls.
This runs Python in Docker — it cannot run Frida scripts, TypeScript, or JavaScript.
For device instrumentation, use run_frida_script instead.`,
		runScriptParams{},
	)
}

func (t *RunScriptTool) Run(ctx context.Context, params tool.ToolCall) (tool.ToolResponse, error) {
	input, err := agent.ParseToolInput[runScriptParams](params.Input)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid input: %v", err)), nil
	}

	if input.Path == "" {
		return tool.NewTextErrorResponse("path is required"), nil
	}

	timeout := 30
	if input.TimeoutSeconds > 0 {
		timeout = input.TimeoutSeconds
	}
	if timeout > 300 {
		timeout = 300
	}

	if err := t.mgr.ensureRunning(ctx); err != nil {
		return tool.NewTextErrorResponse(err.Error()), nil
	}

	containerID := t.mgr.ContainerID()

	cmd := []string{"python", input.Path}
	if input.Args != "" {
		cmd = []string{"sh", "-c", fmt.Sprintf("python %s %s", input.Path, input.Args)}
	}

	start := time.Now()
	stdout, stderr, exitCode, execErr := dockerExec(
		ctx, containerID,
		cmd,
		time.Duration(timeout)*time.Second,
	)
	durationMs := time.Since(start).Milliseconds()

	timedOut := false
	if execErr != nil {
		if strings.Contains(execErr.Error(), "timed out") {
			timedOut = true
		} else {
			return tool.NewTextErrorResponse(fmt.Sprintf("execution failed: %v", execErr)), nil
		}
	}

	type result struct {
		Stdout     string `json:"stdout"`
		Stderr     string `json:"stderr"`
		ExitCode   int    `json:"exit_code"`
		DurationMs int64  `json:"duration_ms"`
		TimedOut   bool   `json:"timed_out"`
		RunID      string `json:"run_id,omitempty"`
	}

	r := result{
		Stdout:     stdout,
		Stderr:     stderr,
		ExitCode:   exitCode,
		DurationMs: durationMs,
		TimedOut:   timedOut,
	}

	if timedOut {
		runID, bgErr := startBackground(ctx, containerID, input.Path, input.Args)
		if bgErr == nil {
			r.RunID = runID
		}
	}

	return tool.NewJSONResponse(r), nil
}

func startBackground(ctx context.Context, containerID, path, args string) (string, error) {
	runID, err := generateRunID()
	if err != nil {
		return "", err
	}

	scriptCmd := fmt.Sprintf("python %s", path)
	if args != "" {
		scriptCmd = fmt.Sprintf("python %s %s", path, args)
	}

	bgCmd := fmt.Sprintf(
		"nohup sh -c '%s > /tmp/sq_%s.out 2> /tmp/sq_%s.err & echo $! > /tmp/sq_%s.pid'",
		scriptCmd, runID, runID, runID,
	)

	_, _, _, err = dockerExec(ctx, containerID, []string{"sh", "-c", bgCmd}, 5*time.Second)
	if err != nil {
		return "", err
	}

	return runID, nil
}

func generateRunID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
