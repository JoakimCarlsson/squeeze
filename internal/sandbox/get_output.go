package sandbox

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/joakimcarlsson/ai/agent"
	"github.com/joakimcarlsson/ai/tool"
)

type getOutputParams struct {
	RunID string `json:"run_id" desc:"The run ID returned by a timed-out docker_run_python call"`
}

type GetOutputTool struct {
	mgr *Manager
}

func (t *GetOutputTool) Info() tool.ToolInfo {
	return tool.NewToolInfo(
		"docker_get_output",
		`Read stdout and stderr from a long-running Python script in the Docker container.
Use the run_id returned by docker_run_python when a script times out — the timed-out script continues running in the background and this tool polls its output.
Only reads output from Docker container processes.
For Frida script output, use get_script_output instead.`,
		getOutputParams{},
	)
}

func (t *GetOutputTool) Run(ctx context.Context, params tool.ToolCall) (tool.ToolResponse, error) {
	input, err := agent.ParseToolInput[getOutputParams](params.Input)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid input: %v", err)), nil
	}

	if input.RunID == "" {
		return tool.NewTextErrorResponse("run_id is required"), nil
	}

	if err := t.mgr.ensureRunning(ctx); err != nil {
		return tool.NewTextErrorResponse(err.Error()), nil
	}

	containerID := t.mgr.ContainerID()

	stdoutFile := fmt.Sprintf("/tmp/sq_%s.out", input.RunID)
	stderrFile := fmt.Sprintf("/tmp/sq_%s.err", input.RunID)
	pidFile := fmt.Sprintf("/tmp/sq_%s.pid", input.RunID)

	pidOut, _, _, err := dockerExec(ctx, containerID, []string{"cat", pidFile}, 5*time.Second)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("run_id %q not found — no matching background execution", input.RunID)), nil
	}
	pid := strings.TrimSpace(pidOut)

	_, _, exitCode, _ := dockerExec(ctx, containerID, []string{"kill", "-0", pid}, 5*time.Second)
	running := exitCode == 0

	stdout, _, _, _ := dockerExec(ctx, containerID, []string{"cat", stdoutFile}, 10*time.Second)
	stderr, _, _, _ := dockerExec(ctx, containerID, []string{"cat", stderrFile}, 10*time.Second)

	type result struct {
		Stdout  string `json:"stdout"`
		Stderr  string `json:"stderr"`
		Running bool   `json:"running"`
	}

	return tool.NewJSONResponse(result{
		Stdout:  stdout,
		Stderr:  stderr,
		Running: running,
	}), nil
}
