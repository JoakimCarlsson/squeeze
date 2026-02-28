package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/joakimcarlsson/ai/agent"
	"github.com/joakimcarlsson/ai/tool"
)

type BashParams struct {
	Command        string `json:"command"                   description:"The bash command to execute"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" description:"Timeout in seconds (default 30)"`
}

type BashTool struct{}

func NewBash() *BashTool {
	return &BashTool{}
}

func (t *BashTool) Info() tool.ToolInfo {
	return tool.NewToolInfo(
		"run_bash",
		"Execute an arbitrary bash command and return stdout, stderr, and exit code.",
		BashParams{},
	)
}

func (t *BashTool) Run(ctx context.Context, params tool.ToolCall) (tool.ToolResponse, error) {
	input, err := agent.ParseToolInput[BashParams](params.Input)
	if err != nil {
		return tool.NewTextErrorResponse(fmt.Sprintf("invalid input: %v", err)), nil
	}

	if input.Command == "" {
		return tool.NewTextErrorResponse("command is required"), nil
	}

	timeout := 30
	if input.TimeoutSeconds > 0 {
		timeout = input.TimeoutSeconds
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", input.Command)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return tool.NewTextErrorResponse(fmt.Sprintf("exec failed: %v", runErr)), nil
		}
	}

	type result struct {
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
		ExitCode int    `json:"exit_code"`
	}

	return tool.NewJSONResponse(result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
	}), nil
}
