package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/PradyumnaKrishna/agy-gate/internal/policy"
	"github.com/PradyumnaKrishna/agy-gate/internal/server"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: agy-gate <command> [args]")
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "serve":
		serve()
	case "eval":
		eval()
	case "version":
		fmt.Println("agy-gate 1.0")
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		os.Exit(1)
	}
}

func serve() {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)

	defaultSock := "/tmp/agy-gate.sock"
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		defaultSock = filepath.Join(xdg, "agy-gate", "gate.sock")
	}

	home := os.Getenv("HOME")
	defaultAudit := filepath.Join(home, ".local", "state", "agy-gate", "audit.jsonl")

	sock := fs.String("socket", defaultSock, "socket path")
	model := fs.String("model", "gemini-3.6-flash-low", "model to use")
	workers := fs.Int("workers", 2, "number of workers")
	recycle := fs.Int("recycle", 15, "requests per worker")
	timeout := fs.Duration("timeout", 40*time.Second, "timeout")
	isolate := fs.Bool("isolate", true, "isolate workers with bwrap")
	audit := fs.String("audit", defaultAudit, "audit log path")
	dryRun := fs.Bool("dry-run", false, "always allow but audit the real decision")

	fs.Parse(os.Args[2:])

	user := os.Getenv("USER")
	agyBin := filepath.Join(home, ".local", "bin", "agy")

	cfg := server.Config{
		Socket:  *sock,
		Model:   *model,
		Workers: *workers,
		Recycle: *recycle,
		Timeout: *timeout,
		Isolate: *isolate,
		Audit:   *audit,
		DryRun:  *dryRun,
		Home:    home,
		User:    user,
		AgyBin:  agyBin,
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start server: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		cancel()
		srv.Stop()
	}()

	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "serve error: %v\n", err)
		os.Exit(1)
	}
}

func eval() {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	useJudge := fs.Bool("judge", false, "actually use judge for uncertain cases")
	fs.Parse(os.Args[2:])

	if fs.NArg() == 0 {
		fmt.Println("Usage: agy-gate eval [-judge] <file.jsonl>")
		os.Exit(1)
	}

	home := os.Getenv("HOME")
	// read cases
	file := fs.Arg(0)
	f, err := os.Open(file)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var cases []struct {
		Tool            string          `json:"tool"`
		Args            json.RawMessage `json:"args"`
		Cwd             string          `json:"cwd"`
		Workspace       []string        `json:"workspace"`
		Expect          string          `json:"expect"`
		ExpectUncertain bool            `json:"expect_uncertain"`
	}

	for scanner.Scan() {
		var c struct {
			Tool            string          `json:"tool"`
			Args            json.RawMessage `json:"args"`
			Cwd             string          `json:"cwd"`
			Workspace       []string        `json:"workspace"`
			Expect          string          `json:"expect"`
			ExpectUncertain bool            `json:"expect_uncertain"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &c); err == nil {
			cases = append(cases, c)
		}
	}

	conf := make(map[string]map[string]int)
	conf["allow"] = make(map[string]int)
	conf["deny"] = make(map[string]int)
	mismatches := 0
	badDenyAllow := false

	for _, c := range cases {
		// Mock payload
		payload, _ := json.Marshal(map[string]interface{}{
			"toolCall": map[string]interface{}{
				"name": c.Tool,
				"args": c.Args,
			},
			"workspacePaths": c.Workspace,
		})

		call, err := policy.DecodeCall(payload, nil)
		if err != nil {
			continue
		}
		call.Cwd = c.Cwd // args JSON might not have Cwd directly as we mapped it in knownArgs but let's override to be safe

		verdict := policy.Decide(call, home)
		var got string
		if verdict.Type == policy.VerdictAllow {
			got = "allow"
		} else if verdict.Type == policy.VerdictDeny {
			got = "deny"
		} else {
			if *useJudge {
				// TODO test actual judge logic if we had one here
				got = "judge"
			} else {
				got = "judge"
			}
		}

		conf[c.Expect][got]++

		if got != c.Expect && !(c.Expect == "deny" && got == "judge") && !(c.Expect == "allow" && got == "judge") {
			fmt.Printf("Mismatch: expected %s, got %s for %s %s\n", c.Expect, got, c.Tool, string(c.Args))
			mismatches++
		}
		if c.Expect == "deny" && got == "allow" && !c.ExpectUncertain {
			badDenyAllow = true
		}
	}

	fmt.Println("Confusion table (expect\\got):")
	fmt.Printf("      \tallow\tdeny\tjudge\n")
	for _, exp := range []string{"allow", "deny"} {
		fmt.Printf("%s\t%d\t%d\t%d\n", exp, conf[exp]["allow"], conf[exp]["deny"], conf[exp]["judge"])
	}

	if badDenyAllow {
		os.Exit(1)
	}
}
