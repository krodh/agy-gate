package main

import (
	"bytes"

	"io"
	"net"
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
	cmd := exec.Command("go", "build", "-o", bin, "main.go")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func TestHookClient(t *testing.T) {
	bin := buildHook(t)

	// no daemon -> deny + exit 0
	t.Run("no daemon", func(t *testing.T) {
		cmd := exec.Command(bin)
		cmd.Env = append(os.Environ(), "AGY_GATE_SOCKET=/no/such/sock")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("expected exit 0, got %v", err)
		}
		if !strings.Contains(string(out), `"decision":"deny"`) {
			t.Errorf("expected deny, got %s", out)
		}
	})

	// AGY_GATE_ROLE=classifier -> deny
	t.Run("classifier", func(t *testing.T) {
		cmd := exec.Command(bin)
		cmd.Env = append(os.Environ(), "AGY_GATE_ROLE=classifier")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("expected exit 0, got %v", err)
		}
		if !strings.Contains(string(out), `"decision":"deny"`) {
			t.Errorf("expected deny, got %s", out)
		}
	})

	// slow daemon -> deny at deadline
	t.Run("slow daemon", func(t *testing.T) {
		sock := filepath.Join(t.TempDir(), "sock")
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()

		go func() {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				// accept but don't read or write
				defer conn.Close()
			}
		}()

		cmd := exec.Command(bin)
		cmd.Env = append(os.Environ(), "AGY_GATE_SOCKET="+sock, "AGY_GATE_TIMEOUT=10ms")
		cmd.Stdin = bytes.NewReader([]byte("{}"))

		start := time.Now()
		out, err := cmd.CombinedOutput()
		dur := time.Since(start)

		if err != nil {
			t.Errorf("expected exit 0, got %v", err)
		}
		if !strings.Contains(string(out), `"decision":"deny"`) {
			t.Errorf("expected deny, got %s", out)
		}
		if dur < 10*time.Millisecond {
			t.Errorf("exited too fast: %v", dur)
		}
	})

	// -post failure -> {}
	t.Run("post failure", func(t *testing.T) {
		cmd := exec.Command(bin, "-post")
		cmd.Env = append(os.Environ(), "AGY_GATE_SOCKET=/no/such/sock")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("expected exit 0, got %v", err)
		}
		if strings.TrimSpace(string(out)) != "{}" {
			t.Errorf("expected {}, got %q", string(out))
		}
	})
}

func BenchmarkHookClient(b *testing.B) {
	// A bit hacky but works for benchmark setup
	dir := b.TempDir()
	bin := filepath.Join(dir, "agy-gate-hook")
	cmd := exec.Command("go", "build", "-o", bin, "main.go")
	if out, err := cmd.CombinedOutput(); err != nil {
		b.Fatalf("build failed: %v\n%s", err, out)
	}

	sock := filepath.Join(dir, "hook-bench.sock")

	l, err := net.Listen("unix", sock)
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(io.Discard, c)
				c.Write([]byte(`{"decision":"allow"}` + "\n"))
			}(conn)
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := exec.Command(bin)
		c.Env = append(os.Environ(), "AGY_GATE_SOCKET="+sock)
		c.Stdin = bytes.NewReader([]byte("{}"))
		if err := c.Run(); err != nil {
			b.Fatal(err)
		}
	}
}
