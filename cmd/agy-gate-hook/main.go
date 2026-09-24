// Command agy-gate-hook is the agy PreToolUse/PostInvocation hook. It forwards
// the raw hook payload to the agy-gate daemon and prints the daemon's reply.
// It never parses JSON and fails closed: any error prints a fixed deny (or {}
// for -post) and exits 0, because agy treats a failing hook as a hard error.
//
// Environment: AGY_GATE_SOCKET (default $XDG_RUNTIME_DIR/agy-gate/gate.sock),
// AGY_GATE_RUN, AGY_GATE_WORKSPACE (colon-separated), AGY_GATE_TIMEOUT
// (Go duration, default 55s), AGY_GATE_ROLE=classifier (deny without asking).
package main

import (
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const deny = `{"decision":"deny","reason":"[agy-gate/hook] the gate daemon is unavailable, so this call was blocked. Do not retry or work around this; stop and report it."}` + "\n"

func main() {
	event := "pre"
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-post":
			event = "post"
		case "-inv":
			event = "inv"
		}
	}
	// A judge worker must never run tools, whatever the daemon would say.
	if os.Getenv("AGY_GATE_ROLE") == "classifier" {
		fail(event)
	}
	sock := os.Getenv("AGY_GATE_SOCKET")
	if sock == "" {
		dir := os.Getenv("XDG_RUNTIME_DIR")
		if dir == "" {
			fail(event) // no /tmp fallback: inside the sandbox /tmp belongs to the agent
		}
		sock = dir + "/agy-gate/gate.sock"
	}
	timeout := 55 * time.Second
	if d, err := time.ParseDuration(os.Getenv("AGY_GATE_TIMEOUT")); err == nil && d > 0 {
		timeout = d
	}

	conn, err := net.DialTimeout("unix", sock, timeout)
	if err != nil {
		fail(event)
	}
	conn.SetDeadline(time.Now().Add(timeout))
	header := "agy-gate/1\t" + event + "\t" + field(os.Getenv("AGY_GATE_RUN")) + "\t" + field(os.Getenv("AGY_GATE_WORKSPACE")) + "\n"
	if _, err := io.WriteString(conn, header); err != nil {
		fail(event)
	}
	if _, err := io.Copy(conn, os.Stdin); err != nil {
		fail(event)
	}
	conn.(*net.UnixConn).CloseWrite()
	reply, err := io.ReadAll(conn)
	if err != nil || len(reply) == 0 {
		fail(event)
	}
	os.Stdout.Write(reply)
}

// field makes a header field safe: never empty, never containing tabs or newlines.
func field(s string) string {
	if s = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s); s == "" {
		return "-"
	}
	return s
}

func fail(event string) {
	if event == "post" || event == "inv" {
		os.Stdout.WriteString("{}\n")
	} else {
		os.Stdout.WriteString(deny)
	}
	os.Exit(0)
}
