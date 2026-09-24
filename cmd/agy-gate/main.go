package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/PradyumnaKrishna/agy-gate/internal/judge"
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

	// Never /tmp: inside the agent sandbox /tmp belongs to the agent.
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = "/run/user/" + strconv.Itoa(os.Getuid())
	}
	defaultSock := filepath.Join(runtimeDir, "agy-gate", "gate.sock")

	home := os.Getenv("HOME")
	defaultAudit := filepath.Join(home, ".local", "state", "agy-gate", "audit.jsonl")

	sock := fs.String("socket", defaultSock, "socket path")
	model := fs.String("model", "gemini-3.6-flash-low", "model to use")
	workers := fs.Int("workers", 2, "number of workers")
	recycle := fs.Int("recycle", 6, "requests per worker before it is replaced (context grows ~2.3k tokens per request)")
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

// evalCase is one line of an eval file.
type evalCase struct {
	Tool            string          `json:"tool"`
	Args            json.RawMessage `json:"args"`
	Cwd             string          `json:"cwd"`
	Workspace       []string        `json:"workspace"`
	UserIntent      string          `json:"user_intent"`
	Expect          string          `json:"expect"`
	ExpectUncertain bool            `json:"expect_uncertain"`
}

// eval runs labelled cases through the policy and, with -judge, through real
// agy judge workers, and prints how each layer decided.
func eval() {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	useJudge := fs.Bool("judge", false, "send cases the policy cannot decide to live agy judge workers")
	model := fs.String("model", "gemini-3.6-flash-low", "judge model")
	workers := fs.Int("workers", 2, "judge workers")
	isolate := fs.Bool("isolate", true, "run judge workers under bwrap")
	fs.Parse(os.Args[2:])
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: agy-gate eval [-judge] [-model m] [-workers n] cases.jsonl")
		os.Exit(2)
	}
	cases, err := readCases(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	home, _ := os.UserHomeDir()

	var pool *judge.Pool
	if *useJudge {
		pool = judge.NewPool(judge.WorkerConfig{
			Model: *model, Isolate: *isolate, Home: home, User: os.Getenv("USER"),
			WorkDir: filepath.Join(home, ".local", "state", "agy-gate", "eval-worker"),
			AgyBin:  filepath.Join(home, ".local", "bin", "agy"),
		}, *workers, 6, 60*time.Second)
	}

	type outcome struct {
		layer, got, reason string
		ms                 int64
	}
	out := make([]outcome, len(cases))
	sem := make(chan struct{}, max(*workers, 1))
	var wg sync.WaitGroup
	for i, c := range cases {
		payload, _ := json.Marshal(map[string]any{"toolCall": map[string]any{"name": c.Tool, "args": c.Args}, "workspacePaths": c.Workspace})
		call, err := policy.DecodeCall(payload, nil)
		if err != nil {
			out[i] = outcome{"error", "deny", err.Error(), 0}
			continue
		}
		if call.Cwd == "" {
			call.Cwd = c.Cwd
		}
		v := policy.Decide(call, home)
		switch {
		case v.Type == policy.VerdictAllow:
			out[i] = outcome{"policy", "allow", "", 0}
			continue
		case v.Type == policy.VerdictDeny:
			out[i] = outcome{"policy", "deny", v.Reason, 0}
			continue
		case pool == nil:
			out[i] = outcome{"judge", "judge", v.Reason, 0}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, call *policy.Call, intent, notes string) {
			defer func() { <-sem; wg.Done() }()
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			reply, err := pool.Ask(ctx, judge.BuildRequest(call, []string{intent}, notes))
			o := outcome{layer: "judge", got: "deny", ms: time.Since(start).Milliseconds()}
			if err == nil {
				if d, perr := judge.ParseReply(reply); perr == nil {
					o.reason = d.Reason
					if d.Allow {
						o.got = "allow"
					}
				} else {
					o.reason = "unparsable reply: " + perr.Error()
				}
			} else {
				o.reason = "judge error: " + err.Error()
			}
			out[i] = o
		}(i, call, c.UserIntent, v.Reason)
	}
	wg.Wait()

	conf := map[string]map[string]int{}
	var lat []int64
	failed := false
	for i, c := range cases {
		o := out[i]
		key := o.layer + ":" + c.Expect
		if conf[key] == nil {
			conf[key] = map[string]int{}
		}
		conf[key][o.got]++
		if o.layer == "judge" && o.ms > 0 {
			lat = append(lat, o.ms)
		}
		if o.got != c.Expect && o.got != "judge" {
			flag := ""
			if c.Expect == "deny" && o.got == "allow" && !c.ExpectUncertain {
				flag, failed = " [FALSE ALLOW]", true
			}
			fmt.Printf("mismatch%s (%s) expect=%s got=%s intent=%q call=%s %s\n    reason: %s\n", flag, o.layer, c.Expect, o.got, c.UserIntent, c.Tool, c.Args, o.reason)
		}
	}
	fmt.Println("\nlayer:expect      allow  deny  judge")
	for _, k := range []string{"policy:allow", "policy:deny", "judge:allow", "judge:deny", "error:allow", "error:deny"} {
		if m := conf[k]; m != nil {
			fmt.Printf("%-16s %6d %5d %6d\n", k, m["allow"], m["deny"], m["judge"])
		}
	}
	if len(lat) > 0 {
		slices.Sort(lat)
		fmt.Printf("\njudge calls: %d, latency p50 %d ms, p95 %d ms, max %d ms\n", len(lat), lat[len(lat)/2], lat[len(lat)*95/100], lat[len(lat)-1])
	}
	if failed {
		os.Exit(1)
	}
}

func readCases(path string) ([]evalCase, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cases []evalCase
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for n := 1; sc.Scan(); n++ {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var c evalCase
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		cases = append(cases, c)
	}
	return cases, sc.Err()
}
