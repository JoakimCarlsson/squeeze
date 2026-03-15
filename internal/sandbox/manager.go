package sandbox

import (
	"context"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/joakimcarlsson/ai/tool"
)

//go:embed image/Dockerfile
var dockerfileFS embed.FS

type ManagerOption func(*Manager)

func WithTimeout(d time.Duration) ManagerOption {
	return func(m *Manager) { m.timeout = d }
}

type Manager struct {
	mu          sync.Mutex
	containerID string
	cancel      context.CancelFunc

	startOnce sync.Once
	startErr  error
	buildOnce sync.Once
	buildErr  error

	timeout time.Duration
	network string
}

func NewManager(opts ...ManagerOption) *Manager {
	m := &Manager{
		timeout: 30 * time.Minute,
		network: "bridge",
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

func (m *Manager) Tools() []tool.BaseTool {
	return []tool.BaseTool{
		&WriteFileTool{mgr: m},
		&EditFileTool{mgr: m},
		&RunScriptTool{mgr: m},
		&GetOutputTool{mgr: m},
	}
}

func (m *Manager) ensureRunning(ctx context.Context) error {
	m.startOnce.Do(func() {
		if err := m.ensureImage(ctx); err != nil {
			m.startErr = err
			return
		}

		opts := defaultRunOpts()
		opts.Network = m.network

		containerID, err := dockerRun(ctx, imageName, opts)
		if err != nil {
			m.startErr = fmt.Errorf("failed to start sandbox: %w", err)
			return
		}

		cancelCtx, cancel := context.WithCancel(context.Background())
		m.mu.Lock()
		m.containerID = containerID
		m.cancel = cancel
		m.mu.Unlock()

		go func() {
			select {
			case <-time.After(m.timeout):
				m.Close()
			case <-cancelCtx.Done():
			}
		}()

		go func() {
			select {
			case <-ctx.Done():
				m.Close()
			case <-cancelCtx.Done():
			}
		}()
	})
	return m.startErr
}

func (m *Manager) ContainerID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.containerID
}

func (m *Manager) Close() {
	m.mu.Lock()
	id := m.containerID
	cancel := m.cancel
	m.containerID = ""
	m.cancel = nil
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if id != "" {
		_ = dockerKill(context.Background(), id)
	}
}

func (m *Manager) ensureImage(ctx context.Context) error {
	m.buildOnce.Do(func() {
		if dockerImageExists(ctx, imageName) {
			return
		}

		tmpDir, err := writeBuildContext()
		if err != nil {
			m.buildErr = fmt.Errorf("prepare build context: %w", err)
			return
		}
		defer os.RemoveAll(tmpDir)

		m.buildErr = dockerBuild(ctx, tmpDir, imageName)
	})
	return m.buildErr
}

func writeBuildContext() (string, error) {
	content, err := dockerfileFS.ReadFile("image/Dockerfile")
	if err != nil {
		return "", err
	}

	tmpDir, err := os.MkdirTemp("", "squeeze-sandbox-build-*")
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), content, 0644); err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}

	return tmpDir, nil
}
