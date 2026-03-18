package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	imageName      = "squeeze-sandbox:latest"
	containerLabel = "squeeze-sandbox=true"
)

type runOpts struct {
	Memory  string
	CPUs    string
	Network string
}

func defaultRunOpts() runOpts {
	return runOpts{
		Memory:  "512m",
		CPUs:    "1",
		Network: "none",
	}
}

func dockerRun(ctx context.Context, image string, opts runOpts) (string, error) {
	args := []string{
		"run", "-d", "--rm",
		"--label", containerLabel,
		"--memory", opts.Memory,
		"--cpus", opts.CPUs,
		"--network", opts.Network,
		"--pids-limit", "256",
		image,
		"sleep", "infinity",
	}

	out, err := dockerCmd(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("docker run: %w", err)
	}

	return strings.TrimSpace(out), nil
}

func dockerExec(ctx context.Context, containerID string, cmd []string, timeout time.Duration) (stdout, stderr string, exitCode int, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := append([]string{"exec", containerID}, cmd...)

	command := exec.CommandContext(ctx, "docker", args...)
	var outBuf, errBuf bytes.Buffer
	command.Stdout = &outBuf
	command.Stderr = &errBuf

	runErr := command.Run()
	stdout, stderr = outBuf.String(), errBuf.String()
	exitCode, err = handleExecResult(ctx, runErr, timeout)
	return
}

func dockerExecWithStdin(ctx context.Context, containerID string, cmd []string, stdin string, timeout time.Duration) (stdout, stderr string, exitCode int, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := append([]string{"exec", "-i", containerID}, cmd...)

	command := exec.CommandContext(ctx, "docker", args...)
	command.Stdin = strings.NewReader(stdin)
	var outBuf, errBuf bytes.Buffer
	command.Stdout = &outBuf
	command.Stderr = &errBuf

	runErr := command.Run()
	stdout, stderr = outBuf.String(), errBuf.String()
	exitCode, err = handleExecResult(ctx, runErr, timeout)
	return
}

func handleExecResult(ctx context.Context, runErr error, timeout time.Duration) (int, error) {
	if runErr == nil {
		return 0, nil
	}

	if ctx.Err() == context.DeadlineExceeded {
		return -1, fmt.Errorf("execution timed out after %v", timeout)
	}

	if exitErr, ok := runErr.(*exec.ExitError); ok {
		return exitErr.ExitCode(), nil
	}

	return -1, fmt.Errorf("docker exec: %w", runErr)
}

func dockerKill(ctx context.Context, containerID string) error {
	_, err := dockerCmd(ctx, "kill", containerID)
	return err
}

func dockerImageExists(ctx context.Context, image string) bool {
	_, err := dockerCmd(ctx, "image", "inspect", image)
	return err == nil
}

func dockerBuild(ctx context.Context, contextDir, tag string) error {
	_, err := dockerCmd(ctx, "build", "-t", tag, contextDir)
	return err
}

func dockerCmd(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}

	return stdout.String(), nil
}
