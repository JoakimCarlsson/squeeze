package sandbox

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/joakimcarlsson/ai/agent"
	"github.com/joakimcarlsson/ai/tool"
)

type writeFileParams struct {
	Path    string `json:"path"    desc:"File path inside the container (e.g. /workspace/exploit.py)"`
	Content string `json:"content" desc:"The full file content to write"`
}

type WriteFileTool struct {
	mgr *Manager
}

func (t *WriteFileTool) Info() tool.ToolInfo {
	return tool.NewToolInfo(
		"docker_write_file",
		`Create or overwrite a file inside the Docker container.
Use this to write Python scripts (.py), wordlists, config files, or any data that docker_run_python will consume.
The Docker container is a completely separate environment from the target device — files written here cannot be accessed by Frida, the app, or any on-device tool.
Do not use this for Frida scripts, TypeScript files, or anything intended to run on the target device.
Automatically lints .py files with py_compile and reports syntax errors.`,
		writeFileParams{},
	)
}

func (t *WriteFileTool) Run(ctx context.Context, params tool.ToolCall) (tool.ToolResponse, error) {
	input, err := agent.ParseToolInput[writeFileParams](params.Input)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid input: %v", err)), nil
	}

	if input.Path == "" {
		return tool.NewTextErrorResponse("path is required"), nil
	}

	if err := t.mgr.ensureRunning(ctx); err != nil {
		return tool.NewTextErrorResponse(err.Error()), nil
	}

	containerID := t.mgr.ContainerID()

	_, stderr, exitCode, err := dockerExecWithStdin(
		ctx, containerID,
		[]string{"tee", input.Path},
		input.Content,
		30*time.Second,
	)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("failed to write file: %v", err)), nil
	}
	if exitCode != 0 {
		return tool.NewTextErrorResponse(fmt.Sprintf("failed to write file: %s", stderr)), nil
	}

	lintPassed, lintOutput := lintPython(ctx, containerID, input.Path)

	type result struct {
		Path       string `json:"path"`
		LintPassed bool   `json:"lint_passed"`
		LintOutput string `json:"lint_output,omitempty"`
	}

	return tool.NewJSONResponse(result{
		Path:       input.Path,
		LintPassed: lintPassed,
		LintOutput: lintOutput,
	}), nil
}

func lintPython(ctx context.Context, containerID, path string) (bool, string) {
	if !strings.HasSuffix(path, ".py") {
		return true, ""
	}

	_, stderr, exitCode, err := dockerExec(
		ctx, containerID,
		[]string{"python", "-m", "py_compile", path},
		10*time.Second,
	)
	if err != nil {
		return false, fmt.Sprintf("lint failed: %v", err)
	}
	if exitCode != 0 {
		return false, strings.TrimSpace(stderr)
	}
	return true, ""
}
