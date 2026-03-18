package tools

import (
	"context"
	"encoding/json"
	"os/exec"
	"testing"

	"github.com/joakimcarlsson/squeeze/internal/sandbox"
)

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed, skipping sandbox test")
	}
	cmd := exec.Command("docker", "info")
	if err := cmd.Run(); err != nil {
		t.Skip("docker daemon not reachable, skipping sandbox test")
	}
}

func newTestManager(t *testing.T) *sandbox.Manager {
	t.Helper()
	mgr := sandbox.NewManager()
	t.Cleanup(mgr.Close)
	return mgr
}

// --- Info tests ---

func TestSandboxTools_Info(t *testing.T) {
	mgr := sandbox.NewManager()
	tools := mgr.Tools()

	expected := []string{
		"docker_write_file",
		"docker_edit_file",
		"docker_run_python",
		"docker_get_output",
	}

	if len(tools) != len(expected) {
		t.Fatalf("expected %d tools, got %d", len(expected), len(tools))
	}

	for i, name := range expected {
		info := tools[i].Info()
		if info.Name != name {
			t.Errorf("tool[%d]: expected name %q, got %q", i, name, info.Name)
		}
		if info.Description == "" {
			t.Errorf("tool[%d] %q: expected non-empty description", i, name)
		}
	}
}

// --- Validation tests (no Docker needed) ---

func TestSandboxWriteFile_EmptyPath(t *testing.T) {
	mgr := sandbox.NewManager()
	tools := mgr.Tools()
	writeTool := tools[0]

	resp, err := writeTool.Run(
		context.Background(),
		makeCall("docker_write_file", `{"path":"","content":"print('hi')"}`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected error for empty path")
	}
}

func TestSandboxEditFile_EmptyOldStr(t *testing.T) {
	mgr := sandbox.NewManager()
	tools := mgr.Tools()
	editTool := tools[1]

	resp, err := editTool.Run(
		context.Background(),
		makeCall("docker_edit_file", `{"path":"/workspace/test.py","old_str":"","new_str":"b"}`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected error for empty old_str")
	}
}

func TestSandboxRunScript_EmptyPath(t *testing.T) {
	mgr := sandbox.NewManager()
	tools := mgr.Tools()
	runTool := tools[2]

	resp, err := runTool.Run(
		context.Background(),
		makeCall("docker_run_python", `{"path":""}`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected error for empty path")
	}
}

func TestSandboxGetOutput_EmptyRunID(t *testing.T) {
	mgr := sandbox.NewManager()
	tools := mgr.Tools()
	getTool := tools[3]

	resp, err := getTool.Run(
		context.Background(),
		makeCall("docker_get_output", `{"run_id":""}`),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected error for empty run_id")
	}
}

// --- Integration tests (require Docker) ---

func TestSandbox_WriteAndRunScript(t *testing.T) {
	requireDocker(t)

	mgr := newTestManager(t)
	tools := mgr.Tools()

	// Write a Python script — this triggers lazy container start
	writeTool := tools[0]
	writeInput, _ := json.Marshal(map[string]string{
		"path":    "/workspace/hello.py",
		"content": "print('hello from sandbox')",
	})
	resp, err := writeTool.Run(context.Background(), makeCall("docker_write_file", string(writeInput)))
	if err != nil {
		t.Fatalf("write_file error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("write_file tool error: %s", resp.Content)
	}

	var writeResult struct {
		Path       string `json:"path"`
		LintPassed bool   `json:"lint_passed"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &writeResult); err != nil {
		t.Fatalf("failed to parse write response: %v", err)
	}
	if !writeResult.LintPassed {
		t.Error("expected lint to pass for valid Python")
	}

	// Run the script
	runTool := tools[2]
	runInput, _ := json.Marshal(map[string]string{
		"path": "/workspace/hello.py",
	})
	resp, err = runTool.Run(context.Background(), makeCall("docker_run_python", string(runInput)))
	if err != nil {
		t.Fatalf("run_script error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("run_script tool error: %s", resp.Content)
	}

	var runResult struct {
		Stdout     string `json:"stdout"`
		Stderr     string `json:"stderr"`
		ExitCode   int    `json:"exit_code"`
		DurationMs int64  `json:"duration_ms"`
		TimedOut   bool   `json:"timed_out"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &runResult); err != nil {
		t.Fatalf("failed to parse run response: %v", err)
	}
	if runResult.Stdout != "hello from sandbox\n" {
		t.Errorf("expected stdout 'hello from sandbox\\n', got %q", runResult.Stdout)
	}
	if runResult.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", runResult.ExitCode)
	}
	if runResult.TimedOut {
		t.Error("expected no timeout")
	}
	if runResult.DurationMs <= 0 {
		t.Error("expected positive duration")
	}
}

func TestSandbox_WriteLintError(t *testing.T) {
	requireDocker(t)

	mgr := newTestManager(t)
	tools := mgr.Tools()

	writeTool := tools[0]
	writeInput, _ := json.Marshal(map[string]string{
		"path":    "/workspace/bad.py",
		"content": "def broken(\n",
	})
	resp, err := writeTool.Run(context.Background(), makeCall("docker_write_file", string(writeInput)))
	if err != nil {
		t.Fatalf("write_file error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("write_file should not be a tool error even with lint failure: %s", resp.Content)
	}

	var result struct {
		LintPassed bool   `json:"lint_passed"`
		LintOutput string `json:"lint_output"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.LintPassed {
		t.Error("expected lint to fail for invalid Python syntax")
	}
	if result.LintOutput == "" {
		t.Error("expected non-empty lint output")
	}
}

func TestSandbox_EditFile(t *testing.T) {
	requireDocker(t)

	mgr := newTestManager(t)
	tools := mgr.Tools()

	// Write initial file
	writeTool := tools[0]
	writeInput, _ := json.Marshal(map[string]string{
		"path":    "/workspace/edit_me.py",
		"content": "msg = 'old value'\nprint(msg)",
	})
	resp, err := writeTool.Run(context.Background(), makeCall("docker_write_file", string(writeInput)))
	if err != nil {
		t.Fatalf("write_file error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("write_file tool error: %s", resp.Content)
	}

	// Edit the file
	editTool := tools[1]
	editInput, _ := json.Marshal(map[string]string{
		"path":    "/workspace/edit_me.py",
		"old_str": "old value",
		"new_str": "new value",
	})
	resp, err = editTool.Run(context.Background(), makeCall("docker_edit_file", string(editInput)))
	if err != nil {
		t.Fatalf("edit_file error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("edit_file tool error: %s", resp.Content)
	}

	var editResult struct {
		LintPassed bool `json:"lint_passed"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &editResult); err != nil {
		t.Fatalf("failed to parse edit response: %v", err)
	}
	if !editResult.LintPassed {
		t.Error("expected lint to pass after edit")
	}

	// Run the edited file to verify
	runTool := tools[2]
	runInput, _ := json.Marshal(map[string]string{
		"path": "/workspace/edit_me.py",
	})
	resp, err = runTool.Run(context.Background(), makeCall("docker_run_python", string(runInput)))
	if err != nil {
		t.Fatalf("run_script error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("run_script tool error: %s", resp.Content)
	}

	var runResult struct {
		Stdout string `json:"stdout"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &runResult); err != nil {
		t.Fatalf("failed to parse run response: %v", err)
	}
	if runResult.Stdout != "new value\n" {
		t.Errorf("expected 'new value\\n', got %q", runResult.Stdout)
	}
}

func TestSandbox_EditFileNotFound(t *testing.T) {
	requireDocker(t)

	mgr := newTestManager(t)
	tools := mgr.Tools()

	editTool := tools[1]
	editInput, _ := json.Marshal(map[string]string{
		"path":    "/workspace/does_not_exist.py",
		"old_str": "a",
		"new_str": "b",
	})
	resp, err := editTool.Run(context.Background(), makeCall("docker_edit_file", string(editInput)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected error when editing nonexistent file")
	}
}

func TestSandbox_EditFileOldStrNotFound(t *testing.T) {
	requireDocker(t)

	mgr := newTestManager(t)
	tools := mgr.Tools()

	writeTool := tools[0]
	writeInput, _ := json.Marshal(map[string]string{
		"path":    "/workspace/test.py",
		"content": "print('hello')",
	})
	writeTool.Run(context.Background(), makeCall("docker_write_file", string(writeInput)))

	editTool := tools[1]
	editInput, _ := json.Marshal(map[string]string{
		"path":    "/workspace/test.py",
		"old_str": "this does not exist",
		"new_str": "replacement",
	})
	resp, err := editTool.Run(context.Background(), makeCall("docker_edit_file", string(editInput)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected error when old_str not found")
	}
}

func TestSandbox_EditFileAmbiguousMatch(t *testing.T) {
	requireDocker(t)

	mgr := newTestManager(t)
	tools := mgr.Tools()

	writeTool := tools[0]
	writeInput, _ := json.Marshal(map[string]string{
		"path":    "/workspace/dup.py",
		"content": "x = 1\nx = 1\n",
	})
	writeTool.Run(context.Background(), makeCall("docker_write_file", string(writeInput)))

	editTool := tools[1]
	editInput, _ := json.Marshal(map[string]string{
		"path":    "/workspace/dup.py",
		"old_str": "x = 1",
		"new_str": "x = 2",
	})
	resp, err := editTool.Run(context.Background(), makeCall("docker_edit_file", string(editInput)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("expected error when old_str matches multiple times")
	}
}

func TestSandbox_RunScriptStderr(t *testing.T) {
	requireDocker(t)

	mgr := newTestManager(t)
	tools := mgr.Tools()

	writeTool := tools[0]
	writeInput, _ := json.Marshal(map[string]string{
		"path":    "/workspace/stderr.py",
		"content": "import sys\nsys.stderr.write('error output\\n')",
	})
	writeTool.Run(context.Background(), makeCall("docker_write_file", string(writeInput)))

	runTool := tools[2]
	runInput, _ := json.Marshal(map[string]string{
		"path": "/workspace/stderr.py",
	})
	resp, err := runTool.Run(context.Background(), makeCall("docker_run_python", string(runInput)))
	if err != nil {
		t.Fatalf("run_script error: %v", err)
	}

	var result struct {
		Stderr   string `json:"stderr"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Stderr != "error output\n" {
		t.Errorf("expected stderr 'error output\\n', got %q", result.Stderr)
	}
}

func TestSandbox_RunScriptNonZeroExit(t *testing.T) {
	requireDocker(t)

	mgr := newTestManager(t)
	tools := mgr.Tools()

	writeTool := tools[0]
	writeInput, _ := json.Marshal(map[string]string{
		"path":    "/workspace/fail.py",
		"content": "import sys\nsys.exit(42)",
	})
	writeTool.Run(context.Background(), makeCall("docker_write_file", string(writeInput)))

	runTool := tools[2]
	runInput, _ := json.Marshal(map[string]string{
		"path": "/workspace/fail.py",
	})
	resp, err := runTool.Run(context.Background(), makeCall("docker_run_python", string(runInput)))
	if err != nil {
		t.Fatalf("run_script error: %v", err)
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

func TestSandbox_RunScriptTimeout(t *testing.T) {
	requireDocker(t)

	mgr := newTestManager(t)
	tools := mgr.Tools()

	writeTool := tools[0]
	writeInput, _ := json.Marshal(map[string]string{
		"path":    "/workspace/slow.py",
		"content": "import time\ntime.sleep(60)",
	})
	writeTool.Run(context.Background(), makeCall("docker_write_file", string(writeInput)))

	runTool := tools[2]
	runInput, _ := json.Marshal(map[string]interface{}{
		"path":            "/workspace/slow.py",
		"timeout_seconds": 2,
	})
	resp, err := runTool.Run(context.Background(), makeCall("docker_run_python", string(runInput)))
	if err != nil {
		t.Fatalf("run_script error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("timeout should not be a tool error: %s", resp.Content)
	}

	var result struct {
		TimedOut bool   `json:"timed_out"`
		RunID    string `json:"run_id"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if !result.TimedOut {
		t.Error("expected timed_out to be true")
	}
}

func TestSandbox_NonPythonFileSkipsLint(t *testing.T) {
	requireDocker(t)

	mgr := newTestManager(t)
	tools := mgr.Tools()

	writeTool := tools[0]
	writeInput, _ := json.Marshal(map[string]string{
		"path":    "/workspace/data.txt",
		"content": "this is not python {{{",
	})
	resp, err := writeTool.Run(context.Background(), makeCall("docker_write_file", string(writeInput)))
	if err != nil {
		t.Fatalf("write_file error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("write_file tool error: %s", resp.Content)
	}

	var result struct {
		LintPassed bool `json:"lint_passed"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if !result.LintPassed {
		t.Error("expected lint_passed=true for non-Python file (lint should be skipped)")
	}
}

func TestSandbox_FullLifecycle(t *testing.T) {
	requireDocker(t)

	mgr := newTestManager(t)
	tools := mgr.Tools()

	// 1. Write a script
	writeTool := tools[0]
	writeInput, _ := json.Marshal(map[string]string{
		"path":    "/workspace/scan.py",
		"content": "results = []\nfor i in range(5):\n    results.append(f'endpoint_{i}: ok')\nprint('\\n'.join(results))",
	})
	resp, err := writeTool.Run(context.Background(), makeCall("docker_write_file", string(writeInput)))
	if err != nil {
		t.Fatalf("write error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("write tool error: %s", resp.Content)
	}

	// 2. Run it
	runTool := tools[2]
	runInput, _ := json.Marshal(map[string]string{
		"path": "/workspace/scan.py",
	})
	resp, err = runTool.Run(context.Background(), makeCall("docker_run_python", string(runInput)))
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("run tool error: %s", resp.Content)
	}

	var runResult struct {
		Stdout   string `json:"stdout"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &runResult); err != nil {
		t.Fatalf("failed to parse run response: %v", err)
	}
	if runResult.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d", runResult.ExitCode)
	}

	// 3. Edit it to add more endpoints
	editTool := tools[1]
	editInput, _ := json.Marshal(map[string]string{
		"path":    "/workspace/scan.py",
		"old_str": "for i in range(5):",
		"new_str": "for i in range(10):",
	})
	resp, err = editTool.Run(context.Background(), makeCall("docker_edit_file", string(editInput)))
	if err != nil {
		t.Fatalf("edit error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("edit tool error: %s", resp.Content)
	}

	// 4. Re-run
	resp, err = runTool.Run(context.Background(), makeCall("docker_run_python", string(runInput)))
	if err != nil {
		t.Fatalf("re-run error: %v", err)
	}

	if err := json.Unmarshal([]byte(resp.Content), &runResult); err != nil {
		t.Fatalf("failed to parse re-run response: %v", err)
	}
	if runResult.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d", runResult.ExitCode)
	}

	lines := 0
	for _, c := range runResult.Stdout {
		if c == '\n' {
			lines++
		}
	}
	if lines != 10 {
		t.Errorf("expected 10 output lines after edit, got %d", lines)
	}
}

func TestSandbox_NetworkAccess(t *testing.T) {
	requireDocker(t)

	mgr := newTestManager(t)
	tools := mgr.Tools()

	writeTool := tools[0]
	writeInput, _ := json.Marshal(map[string]string{
		"path": "/workspace/net_test.py",
		"content": `import urllib.request
try:
    resp = urllib.request.urlopen("https://httpbin.org/get", timeout=10)
    print(f"status:{resp.status}")
except Exception as e:
    print(f"error:{e}")
`,
	})
	resp, err := writeTool.Run(context.Background(), makeCall("docker_write_file", string(writeInput)))
	if err != nil {
		t.Fatalf("write_file error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("write_file tool error: %s", resp.Content)
	}

	runTool := tools[2]
	runInput, _ := json.Marshal(map[string]string{
		"path": "/workspace/net_test.py",
	})
	resp, err = runTool.Run(context.Background(), makeCall("docker_run_python", string(runInput)))
	if err != nil {
		t.Fatalf("run_script error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("run_script tool error: %s", resp.Content)
	}

	var result struct {
		Stdout   string `json:"stdout"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d (stderr may have details)", result.ExitCode)
	}
	if result.Stdout != "status:200\n" {
		t.Errorf("expected 'status:200\\n', got %q", result.Stdout)
	}
}
