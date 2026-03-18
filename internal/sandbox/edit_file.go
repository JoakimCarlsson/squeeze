package sandbox

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/joakimcarlsson/ai/agent"
	"github.com/joakimcarlsson/ai/tool"
)

type editFileParams struct {
	Path   string `json:"path"    desc:"File path inside the container to edit"`
	OldStr string `json:"old_str" desc:"Exact text to find and replace (must appear exactly once)"`
	NewStr string `json:"new_str" desc:"Replacement text"`
}

type EditFileTool struct {
	mgr *Manager
}

func (t *EditFileTool) Info() tool.ToolInfo {
	return tool.NewToolInfo(
		"docker_edit_file",
		`Edit an existing file inside the Docker container using exact string replacement.
The old_str must appear exactly once in the file — include surrounding context to disambiguate if needed.
Use this to iterate on Python scripts after reviewing docker_run_python output.
Only affects files inside the Docker container — cannot edit files on the target device.
Automatically lints .py files with py_compile.`,
		editFileParams{},
	)
}

func (t *EditFileTool) Run(ctx context.Context, params tool.ToolCall) (tool.ToolResponse, error) {
	input, err := agent.ParseToolInput[editFileParams](params.Input)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid input: %v", err)), nil
	}

	if input.Path == "" {
		return tool.NewTextErrorResponse("path is required"), nil
	}
	if input.OldStr == "" {
		return tool.NewTextErrorResponse("old_str is required"), nil
	}

	if err := t.mgr.ensureRunning(ctx); err != nil {
		return tool.NewTextErrorResponse(err.Error()), nil
	}

	containerID := t.mgr.ContainerID()

	stdout, _, exitCode, err := dockerExec(
		ctx, containerID,
		[]string{"cat", input.Path},
		10*time.Second,
	)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("failed to read file: %v", err)), nil
	}
	if exitCode != 0 {
		return tool.NewTextErrorResponse(fmt.Sprintf("file not found: %s", input.Path)), nil
	}

	content := stdout
	count := strings.Count(content, input.OldStr)
	if count == 0 {
		return tool.NewTextErrorResponse("old_str not found in file"), nil
	}
	if count > 1 {
		return tool.NewTextErrorResponse(fmt.Sprintf("old_str appears %d times — it must be unique. Include more surrounding context to disambiguate", count)), nil
	}

	newContent := strings.Replace(content, input.OldStr, input.NewStr, 1)

	_, stderr, exitCode, err := dockerExecWithStdin(
		ctx, containerID,
		[]string{"tee", input.Path},
		newContent,
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
