package test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/joakimcarlsson/ai/tool"
	"github.com/joakimcarlsson/squeeze/internal/tools"
)

func makeCall(name, input string) tool.ToolCall {
	return tool.ToolCall{ID: "test-1", Name: name, Input: input}
}

func TestRunBash_Info(t *testing.T) {
	s := tools.NewBash()
	info := s.Info()
	if info.Name != "run_bash" {
		t.Fatalf("expected name run_bash, got %s", info.Name)
	}
}

func TestRunBash_EchoStdout(t *testing.T) {
	s := tools.NewBash()
	resp, err := s.Run(
		context.Background(),
		makeCall("run_bash", `{"command":"echo hello"}`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("unexpected tool error: %s", resp.Content)
	}

	var result struct {
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Stdout != "hello\n" {
		t.Errorf("expected stdout 'hello\\n', got %q", result.Stdout)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
}

func TestRunBash_Stderr(t *testing.T) {
	s := tools.NewBash()
	resp, err := s.Run(
		context.Background(),
		makeCall("run_bash", `{"command":"echo err >&2"}`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result struct {
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Stderr != "err\n" {
		t.Errorf("expected stderr 'err\\n', got %q", result.Stderr)
	}
}

func TestRunBash_NonZeroExitCode(t *testing.T) {
	s := tools.NewBash()
	resp, err := s.Run(
		context.Background(),
		makeCall("run_bash", `{"command":"exit 42"}`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("non-zero exit should not be a tool error: %s", resp.Content)
	}

	var result struct {
		ExitCode int `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.ExitCode != 42 {
		t.Errorf("expected exit code 42, got %d", result.ExitCode)
	}
}

func TestRunBash_Timeout(t *testing.T) {
	s := tools.NewBash()
	resp, err := s.Run(
		context.Background(),
		makeCall("run_bash", `{"command":"sleep 10","timeout_seconds":1}`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		var result struct {
			ExitCode int `json:"exit_code"`
		}
		if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}
		if result.ExitCode == 0 {
			t.Fatal("expected timeout to cause non-zero exit or error")
		}
	}
}

func TestRunBash_EmptyCommand(t *testing.T) {
	s := tools.NewBash()
	resp, err := s.Run(
		context.Background(),
		makeCall("run_bash", `{"command":""}`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected error for empty command")
	}
}

func TestRunBash_StdoutAndStderr(t *testing.T) {
	s := tools.NewBash()
	resp, err := s.Run(
		context.Background(),
		makeCall("run_bash", `{"command":"echo out && echo err >&2"}`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result struct {
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Stdout != "out\n" {
		t.Errorf("expected stdout 'out\\n', got %q", result.Stdout)
	}
	if result.Stderr != "err\n" {
		t.Errorf("expected stderr 'err\\n', got %q", result.Stderr)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
}
