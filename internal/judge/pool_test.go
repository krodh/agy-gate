package judge

import (
	"bufio"
	"context"

	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("BE_FAKE_AGY") == "1" {
		fakeAgy()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeAgy() {
	scanner := bufio.NewScanner(os.Stdin)
	reqs := 0

	// Read args to determine behavior
	crash := false
	malformed := false
	timeout := false
	quota := false

	for _, arg := range os.Args {
		if arg == "CRASH" {
			crash = true
		}
		if arg == "MALFORMED" {
			malformed = true
		}
		if arg == "TIMEOUT" {
			timeout = true
		}
		if arg == "QUOTA" {
			quota = true
		}
	}

	for scanner.Scan() {
		reqs++
		if crash {
			os.Exit(1)
		}
		if timeout {
			time.Sleep(2 * time.Second) // exceed standard timeout
		}

		if quota {
			fmt.Println(`{"event":"result","result":{"status":"ERROR","error":"RESOURCE_EXHAUSTED"}}`)
			continue
		}

		if malformed {
			fmt.Println(`{"event":"result","result":{"status":"SUCCESS","response":"{malformed json}"}}`)
			continue
		}

		// Normal reply
		fmt.Printf(`{"event":"result","result":{"status":"SUCCESS","response":"{\"decision\":\"allow\",\"reason\":\"\"}"}}` + "\n")
	}
}

func TestPool(t *testing.T) {
	wd, _ := os.MkdirTemp("", "pool-test")
	defer os.RemoveAll(wd)
	cfg := WorkerConfig{
		Model:   "fake",
		Isolate: false,
		WorkDir: wd,
		AgyBin:  os.Args[0], // re-exec self
	}

	os.Setenv("BE_FAKE_AGY", "1")
	defer os.Unsetenv("BE_FAKE_AGY")

	t.Run("warm-up and recycle", func(t *testing.T) {
		p := NewPool(cfg, 1, 2, 1*time.Second)
		time.Sleep(100 * time.Millisecond) // allow warm-up

		// Ask 1 -> should succeed
		res, err := p.Ask(context.Background(), "test")
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if !strings.Contains(res, "allow") {
			t.Fatalf("expected allow, got %s", res)
		}

		// Ask 2 -> hits recycle limit and replaces worker
		_, err = p.Ask(context.Background(), "test")
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
	})

	t.Run("dead workers are never handed out", func(t *testing.T) {
		crashCfg := cfg
		crashCfg.Model = "CRASH" // the fake agy sees --model CRASH and exits on its first message
		p := NewPool(crashCfg, 1, 5, 500*time.Millisecond)
		time.Sleep(100 * time.Millisecond)

		// Every worker dies during warm-up, so none may reach callers: the call
		// must fail waiting for a worker, not with a broken pipe from a dead one.
		_, err := p.Ask(context.Background(), "test")
		if err == nil || !strings.Contains(err.Error(), "timeout waiting for worker") {
			t.Fatalf("want timeout waiting for worker, got %v", err)
		}
	})

	t.Run("quota backoff", func(t *testing.T) {
		quotaCfg := cfg
		quotaCfg.Model = "QUOTA"
		p := NewPool(quotaCfg, 1, 5, 500*time.Millisecond)
		time.Sleep(100 * time.Millisecond)

		_, err := p.Ask(context.Background(), "test")
		if err == nil || !strings.Contains(err.Error(), "RESOURCE_EXHAUSTED") {
			t.Fatalf("expected RESOURCE_EXHAUSTED, got %v", err)
		}

		// Try again immediately -> should fast deny
		start := time.Now()
		_, err = p.Ask(context.Background(), "test")
		if err == nil || !strings.Contains(err.Error(), "RESOURCE_EXHAUSTED") {
			t.Fatalf("expected fast RESOURCE_EXHAUSTED, got %v", err)
		}
		if time.Since(start) > 100*time.Millisecond {
			t.Fatal("expected fast deny")
		}
	})
}
