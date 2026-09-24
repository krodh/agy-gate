package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/PradyumnaKrishna/agy-gate/internal/judge"
	"github.com/PradyumnaKrishna/agy-gate/internal/policy"
)

type Config struct {
	Socket  string
	Model   string
	Workers int
	Recycle int
	Timeout time.Duration
	Isolate bool
	Audit   string
	DryRun  bool
	Home    string
	User    string
	AgyBin  string
}

type Server struct {
	cfg   Config
	pool  *judge.Pool
	audit *os.File

	mu        sync.Mutex
	cache     map[string]judge.Decision
	denials   map[string]*DenialCounter
	listeners []net.Listener
}

type DenialCounter struct {
	Consecutive int
	Total       int
}

type AuditLog struct {
	Ts       string `json:"ts"`
	Run      string `json:"run"`
	Conv     string `json:"conv"`
	Step     int    `json:"step"`
	Tool     string `json:"tool"`
	Subject  string `json:"subject"`
	Layer    string `json:"layer"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	Ms       int64  `json:"ms"`
	DryRun   bool   `json:"dry_run"`
}

func NewServer(cfg Config) (*Server, error) {
	wd := filepath.Join(cfg.Home, ".local", "state", "agy-gate", "worker")
	os.MkdirAll(wd, 0700)

	pool := judge.NewPool(judge.WorkerConfig{
		Model:   cfg.Model,
		Isolate: cfg.Isolate,
		WorkDir: wd,
		Home:    cfg.Home,
		User:    cfg.User,
		AgyBin:  cfg.AgyBin,
	}, cfg.Workers, cfg.Recycle, cfg.Timeout)

	var audit *os.File
	if cfg.Audit != "" {
		os.MkdirAll(filepath.Dir(cfg.Audit), 0700)
		f, err := os.OpenFile(cfg.Audit, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		audit = f
	}

	return &Server{
		cfg:     cfg,
		pool:    pool,
		audit:   audit,
		cache:   make(map[string]judge.Decision),
		denials: make(map[string]*DenialCounter),
	}, nil
}

func (s *Server) Serve(ctx context.Context) error {
	os.MkdirAll(filepath.Dir(s.cfg.Socket), 0700)

	// Check for stale socket
	if _, err := os.Stat(s.cfg.Socket); err == nil {
		conn, err := net.DialTimeout("unix", s.cfg.Socket, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return fmt.Errorf("another daemon is answering on %s", s.cfg.Socket)
		}
		os.Remove(s.cfg.Socket)
	}

	ln, err := net.Listen("unix", s.cfg.Socket)
	if err != nil {
		return err
	}
	os.Chmod(s.cfg.Socket, 0600)

	s.mu.Lock()
	s.listeners = append(s.listeners, ln)
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go s.handle(conn)
	}
}

// maxPayload bounds one hook request.
const maxPayload = 16 << 20

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	start := time.Now()

	// Payloads carry whole file contents for write_to_file, so the cap is generous.
	br := bufio.NewReader(io.LimitReader(conn, maxPayload))
	header, err := br.ReadString('\n')
	if err != nil {
		return
	}
	// Header: "agy-gate/1\t<pre|post>\t<run-id>\t<ws1:ws2>\n"; "-" marks an empty field.
	parts := strings.Split(strings.TrimRight(header, "\n"), "\t")
	if len(parts) != 4 || parts[0] != "agy-gate/1" {
		return // the client treats a missing reply as deny
	}
	event, runID := parts[1], parts[2]
	if runID == "-" {
		runID = ""
	}
	var wsList []string
	if parts[3] != "-" && parts[3] != "" {
		wsList = strings.Split(parts[3], ":")
	}

	payload, err := io.ReadAll(br)
	if err != nil {
		return
	}

	call, err := policy.DecodeCall(payload, wsList)
	if err != nil || call == nil {
		if event == "post" {
			conn.Write([]byte("{}\n"))
		} else {
			resBytes, _ := json.Marshal(map[string]string{
				"decision": "deny",
				"reason":   "[agy-gate/server] payload decode failed. Do not retry or work around this; use a safer approach or stop and report what you need.",
			})
			conn.Write(resBytes)
			conn.Write([]byte("\n"))
		}
		return
	}

	// 2. Policy (deterministic layer)
	verdict := policy.Decide(call, s.cfg.Home)

	decision := "judge"
	reason := verdict.Reason
	layer := "policy"

	if verdict.Type == policy.VerdictAllow {
		decision = "allow"
	} else if verdict.Type == policy.VerdictDeny {
		decision = "deny"
		reason = fmt.Sprintf("[agy-gate/policy] %s. Do not retry or work around this; use a safer approach or stop and report what you need.", reason)
	} else {
		// 3. Cache and 4. Judge
		cacheKey := s.cacheKey(call)
		s.mu.Lock()
		if cached, ok := s.cache[cacheKey]; ok {
			s.mu.Unlock()
			decision = "allow"
			if !cached.Allow {
				decision = "deny"
				reason = cached.Reason
			}
			layer = "cache"
		} else {
			s.mu.Unlock()

			transcript, _ := judge.ReadTranscript(call.TranscriptPath, call.ConversationID)
			reqBody := judge.BuildRequest(call, transcript, reason)

			// Try judge
			replyStr, err := s.pool.Ask(context.Background(), reqBody)
			layer = "judge"
			if err != nil {
				decision = "deny"
				reason = fmt.Sprintf("[agy-gate/judge] error: %v. Do not retry or work around this; use a safer approach or stop and report what you need.", err)
			} else {
				parsed, err := judge.ParseReply(replyStr)
				if err != nil {
					decision = "deny"
					reason = "[agy-gate/judge] malformed reply. Do not retry or work around this; use a safer approach or stop and report what you need."
				} else {
					if parsed.Allow {
						decision = "allow"
					} else {
						decision = "deny"
						reason = fmt.Sprintf("[agy-gate/judge] %s. Do not retry or work around this; use a safer approach or stop and report what you need.", parsed.Reason)
					}

					// Cache judged verdicts
					s.mu.Lock()
					if len(s.cache) >= 4096 {
						s.cache = make(map[string]judge.Decision) // Drop cache if full
					}
					s.cache[cacheKey] = judge.Decision{Allow: parsed.Allow, Reason: reason}
					s.mu.Unlock()
				}
			}
		}
	}

	// 5. Limits
	if decision == "deny" {
		if event == "pre" {
			s.mu.Lock()
			c, ok := s.denials[call.ConversationID]
			if !ok {
				c = &DenialCounter{}
				s.denials[call.ConversationID] = c
			}
			c.Consecutive++
			c.Total++
			s.mu.Unlock()
		}
	} else {
		if event == "pre" {
			s.mu.Lock()
			if c, ok := s.denials[call.ConversationID]; ok {
				c.Consecutive = 0
			}
			s.mu.Unlock()
		}
	}

	s.mu.Lock()
	c := s.denials[call.ConversationID]
	isEscalated := c != nil && (c.Consecutive >= 3 || c.Total >= 20)
	s.mu.Unlock()

	if decision == "deny" && isEscalated {
		reason = "ESCALATED: " + reason
	}

	// Apply Dry Run
	auditDecision := decision
	if s.cfg.DryRun {
		decision = "allow"
	}

	// Reply
	if event == "post" {
		if isEscalated {
			conn.Write([]byte("{\"terminationBehavior\":\"terminate\"}\n"))
		} else {
			conn.Write([]byte("{}\n"))
		}
	} else {
		resBytes, _ := json.Marshal(map[string]string{
			"decision": decision,
			"reason":   reason,
		})
		conn.Write(resBytes)
		conn.Write([]byte("\n"))
	}

	// 6. Audit
	if s.audit != nil {
		subject := call.CommandLine
		if subject == "" {
			subject = call.TargetFile
		}
		if subject == "" {
			subject = call.AbsolutePath
		}
		if subject == "" {
			subject = call.DirectoryPath
		}
		if subject == "" {
			subject = call.Url
		}
		if len(subject) > 300 {
			subject = subject[:297] + "..."
		}

		logEntry := AuditLog{
			Ts:       time.Now().UTC().Format(time.RFC3339),
			Run:      runID,
			Conv:     call.ConversationID,
			Step:     call.StepIdx,
			Tool:     call.Tool,
			Subject:  subject,
			Layer:    layer,
			Decision: auditDecision,
			Reason:   reason,
			Ms:       time.Since(start).Milliseconds(),
			DryRun:   s.cfg.DryRun,
		}
		b, _ := json.Marshal(logEntry)
		b = append(b, '\n')
		s.mu.Lock()
		s.audit.Write(b)
		s.mu.Unlock()
	}
}

func (s *Server) cacheKey(call *policy.Call) string {
	// sha256(conversation, tool, canonical args, cwd, workspace)
	h := sha256.New()
	h.Write([]byte(call.ConversationID))
	h.Write([]byte(call.Tool))

	// Canonical args (exclude toolAction, toolSummary, WaitMsBeforeAsync)
	h.Write([]byte(call.CommandLine))
	h.Write([]byte(call.TargetFile))
	h.Write([]byte(call.AbsolutePath))
	h.Write([]byte(call.DirectoryPath))
	h.Write([]byte(call.SearchPath))
	h.Write([]byte(call.SearchDirectory))
	h.Write([]byte(call.Url))

	h.Write([]byte(call.Cwd))
	for _, ws := range call.Workspace {
		h.Write([]byte(ws))
	}

	// Hash executed scripts in workspace
	if call.Tool == "run_command" {
		for _, w := range strings.Fields(call.CommandLine) {
			w = strings.Trim(w, `"'`)
			p := w
			if !filepath.IsAbs(p) {
				p = filepath.Join(call.Cwd, p)
			}
			if info, err := os.Stat(p); err == nil && !info.IsDir() {
				inWs := false
				for _, ws := range call.Workspace {
					if strings.HasPrefix(p, ws) {
						inWs = true
						break
					}
				}
				if inWs {
					if b, err := os.ReadFile(p); err == nil {
						h.Write(b)
					}
				}
			}
		}
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ln := range s.listeners {
		ln.Close()
	}
	// Pool doesn't need explicit shutdown, but we could add it
	if s.audit != nil {
		s.audit.Close()
	}
}
