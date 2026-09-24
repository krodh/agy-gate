package server

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func buildHook(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "agy-gate-hook")
	// The main.go is in cmd/agy-gate-hook
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd/agy-gate-hook/main.go")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func TestServerEndToEndAndLimits(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "gate.sock")
	cfg := Config{
		Socket:  sock,
		Model:   "fake",
		Workers: 1,
		Recycle: 10,
		Timeout: 2 * time.Second,
		Isolate: false,
		Home:    t.TempDir(),
		User:    "test",
		AgyBin:  "echo", // doesn't matter, we'll hit deterministic deny
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := srv.Serve(ctx); err != nil {
			t.Logf("Serve ended: %v", err)
		}
	}()

	// Wait for socket
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	hookBin := buildHook(t)

	runHook := func(event, payload, convID string) string {
		cmd := exec.Command(hookBin)
		if event == "post" {
			cmd.Args = append(cmd.Args, "-post")
		}
		cmd.Env = append(os.Environ(), "AGY_GATE_SOCKET="+sock, "AGY_GATE_RUN=test-run")

		p := map[string]any{
			"toolCall": map[string]any{
				"name": "run_command",
				"args": map[string]any{"CommandLine": payload},
			},
			"conversationId": convID,
		}
		b, _ := json.Marshal(p)
		cmd.Stdin = bytes.NewReader(b)

		out, _ := cmd.CombinedOutput()
		t.Logf("runHook %s -> %s", event, string(out))
		return string(out)
	}

	convID := "conv-limits"

	// 1st deny
	out := runHook("pre", "sudo rm -rf /", convID)
	if !strings.Contains(out, "deny") || strings.Contains(out, "ESCALATED") {
		t.Fatalf("expected plain deny, got %s", out)
	}

	// 2nd deny
	out = runHook("pre", "sudo rm -rf /", convID)
	if !strings.Contains(out, "deny") || strings.Contains(out, "ESCALATED") {
		t.Fatalf("expected plain deny, got %s", out)
	}

	// 3rd deny -> escalated
	out = runHook("pre", "sudo rm -rf /", convID)
	if !strings.Contains(out, "ESCALATED") {
		t.Fatalf("expected ESCALATED deny, got %s", out)
	}

	// post hook when escalated
	out = runHook("post", "sudo rm -rf /", convID)
	if !strings.Contains(out, "terminationBehavior") {
		t.Fatalf("expected terminationBehavior, got %s", out)
	}

	// allow resets counter
	out = runHook("pre", "ls", convID)
	if !strings.Contains(out, "allow") {
		t.Fatalf("expected allow, got %s", out)
	}

	// 1st deny again
	out = runHook("pre", "sudo rm -rf /", convID)
	if !strings.Contains(out, "deny") || strings.Contains(out, "ESCALATED") {
		t.Fatalf("expected plain deny after reset, got %s", out)
	}

	// A real PostInvocation payload has no toolCall. It must be answered from the
	// denial counters alone: never judged, never counted as a denial.
	for i := 0; i < 4; i++ {
		post := exec.Command(hookBin, "-post")
		post.Env = append(os.Environ(), "AGY_GATE_SOCKET="+sock)
		post.Stdin = strings.NewReader(`{"conversationId":"conv-post","invocationNum":1,"initialNumSteps":3}`)
		start := time.Now()
		got, _ := post.Output()
		if strings.TrimSpace(string(got)) != "{}" || time.Since(start) > time.Second {
			t.Fatalf("post event: got %q after %v, want {} immediately", got, time.Since(start))
		}
	}
}
