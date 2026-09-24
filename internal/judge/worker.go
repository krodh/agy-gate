package judge

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

type Worker struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Scanner
	mu     sync.Mutex
	uses   int
	done   chan struct{}
}

type WorkerConfig struct {
	Model   string
	Isolate bool
	WorkDir string
	Home    string
	User    string
	AgyBin  string
}

type requestPayload struct {
	Event   string `json:"event"`
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
}

type responseEvent struct {
	Event  string `json:"event"`
	Result struct {
		Status   string `json:"status"`
		Response string `json:"response"`
		Error    string `json:"error"`
		Usage    struct {
			InputTokens int `json:"input_tokens"`
		} `json:"usage"`
	} `json:"result"`
}

// writeWorkerFiles creates the judge agent definition (no tools, no default
// prompt sections) and an agy settings file that allows nothing.
func writeWorkerFiles(wd string) error {
	agents := filepath.Join(wd, ".agents", "agents")
	if err := os.MkdirAll(agents, 0o700); err != nil {
		return fmt.Errorf("worker dir: %w", err)
	}
	settings, err := json.Marshal(map[string]any{
		"permissions":       map[string][]string{"allow": {}},
		"trustedWorkspaces": []string{wd},
	})
	if err != nil {
		return err
	}
	agent := "---\nname: agy-gate-judge\ndescription: agy-gate permission judge\nexcludeDefaultComponents: true\ntools: []\nsubagent: false\n---\n# agy-gate judge\n\n" + promptData
	if err := os.WriteFile(filepath.Join(wd, "settings.json"), settings, 0o600); err != nil {
		return fmt.Errorf("worker settings: %w", err)
	}
	if err := os.WriteFile(filepath.Join(agents, "agy-gate-judge.md"), []byte(agent), 0o600); err != nil {
		return fmt.Errorf("judge agent: %w", err)
	}
	return nil
}

func StartWorker(ctx context.Context, cfg WorkerConfig) (*Worker, error) {
	// agy ignores an agent's frontmatter unless --add-dir is absolute.
	wd, err := filepath.Abs(cfg.WorkDir)
	if err != nil {
		return nil, fmt.Errorf("worker dir: %w", err)
	}
	if err := writeWorkerFiles(wd); err != nil {
		return nil, err
	}
	settingsPath := filepath.Join(wd, "settings.json")

	var cmd *exec.Cmd
	if cfg.Isolate {
		args := []string{
			"--ro-bind", "/", "/",
			"--dev", "/dev",
			"--proc", "/proc",
			"--tmpfs", "/tmp",
			"--tmpfs", "/run/user",
			"--tmpfs", cfg.Home,
			"--ro-bind", cfg.AgyBin, cfg.AgyBin,
			"--bind", filepath.Join(cfg.Home, ".gemini"), filepath.Join(cfg.Home, ".gemini"),
			"--bind", filepath.Join(cfg.Home, ".cache", "antigravity"), filepath.Join(cfg.Home, ".cache", "antigravity"),
			"--bind", wd, wd,
			"--ro-bind", settingsPath, filepath.Join(cfg.Home, ".gemini", "antigravity-cli", "settings.json"),
			"--unshare-pid", "--unshare-ipc", "--die-with-parent", "--new-session", "--clearenv",
			"--setenv", "HOME", cfg.Home,
			"--setenv", "USER", cfg.User,
			"--setenv", "TERM", "dumb",
			"--setenv", "PATH", cfg.Home + "/.local/bin:/usr/local/bin:/usr/bin:/bin",
			"--setenv", "AGY_GATE_ROLE", "classifier",
			"--chdir", wd,
			"--", cfg.AgyBin, "--agent", "agy-gate-judge", "--add-dir", wd, "--model", cfg.Model,
			"--input-format", "stream-json", "--output-format", "stream-json", "-p=",
		}
		cmd = exec.CommandContext(ctx, "bwrap", args...)
	} else {
		cmd = exec.CommandContext(ctx, cfg.AgyBin, "--agent", "agy-gate-judge", "--add-dir", wd, "--model", cfg.Model,
			"--input-format", "stream-json", "--output-format", "stream-json", "-p=")
		cmd.Dir = wd
		cmd.Env = append(os.Environ(), "AGY_GATE_ROLE=classifier")
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return &Worker{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewScanner(stdout),
		done:   make(chan struct{}),
	}, nil
}

func (w *Worker) Ask(ctx context.Context, msg string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.uses++

	req := requestPayload{Event: "user"}
	req.Message.Content = msg

	b, _ := json.Marshal(req)
	b = append(b, '\n')
	if _, err := w.stdin.Write(b); err != nil {
		return "", err
	}

	type result struct {
		reply string
		err   error
	}
	resCh := make(chan result, 1)

	go func() {
		for w.stdout.Scan() {
			var ev responseEvent
			if err := json.Unmarshal(w.stdout.Bytes(), &ev); err != nil {
				continue
			}
			if ev.Event == "result" {
				if ev.Result.Status == "ERROR" {
					resCh <- result{err: fmt.Errorf("worker error: %s", ev.Result.Error)}
					return
				}
				resCh <- result{reply: ev.Result.Response}
				return
			}
		}
		if err := w.stdout.Err(); err != nil {
			resCh <- result{err: err}
		} else {
			resCh <- result{err: fmt.Errorf("worker closed stdout")}
		}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-resCh:
		return res.reply, res.err
	}
}

func (w *Worker) Close() {
	w.stdin.Close()
	// Ignore errors from kill
	w.cmd.Process.Kill()
	w.cmd.Wait()
}
