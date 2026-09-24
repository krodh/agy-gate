package judge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Pool struct {
	cfg        WorkerConfig
	numWorkers int
	recycle    int
	timeout    time.Duration

	mu         sync.Mutex
	workers    chan *Worker
	quotaUntil time.Time
}

func NewPool(cfg WorkerConfig, numWorkers int, recycle int, timeout time.Duration) *Pool {
	p := &Pool{
		cfg:        cfg,
		numWorkers: numWorkers,
		recycle:    recycle,
		timeout:    timeout,
		workers:    make(chan *Worker, numWorkers),
	}

	// Start initial workers
	for i := 0; i < numWorkers; i++ {
		go p.startOne()
	}

	return p
}

// startOne spawns and warms a worker, and only adds it to the pool once it has
// answered. A worker that fails to start or warm up is closed (which reaps it)
// and retried with exponential backoff, so the pool never hands out a dead
// worker and heals itself once the cause (quota, network, sandbox) goes away.
func (p *Pool) startOne() {
	for delay := 2 * time.Second; ; delay = min(delay*2, time.Minute) {
		w, err := StartWorker(context.Background(), p.cfg)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
			_, err = w.Ask(ctx, "warmup")
			cancel()
			if err == nil {
				p.workers <- w
				return
			}
			w.Close()
		}
		if isQuota(err) {
			p.setQuotaErr() // callers get a fast deny instead of waiting for a worker
		}
		time.Sleep(delay)
	}
}

func (p *Pool) get() (*Worker, error) {
	p.mu.Lock()
	if time.Now().Before(p.quotaUntil) {
		p.mu.Unlock()
		return nil, errors.New("RESOURCE_EXHAUSTED")
	}
	p.mu.Unlock()

	select {
	case w := <-p.workers:
		return w, nil
	case <-time.After(p.timeout):
		return nil, errors.New("timeout waiting for worker")
	}
}

func (p *Pool) put(w *Worker, bad bool) {
	if bad {
		w.Close()
		go p.startOne()
		return
	}

	if p.recycle > 0 && w.uses >= p.recycle {
		w.Close()
		go p.startOne()
		return
	}

	p.workers <- w
}

// isQuota reports whether err is agy's quota or rate-limit error.
func isQuota(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "quota") || strings.Contains(msg, "RESOURCE_EXHAUSTED") || strings.Contains(msg, "429")
}

func (p *Pool) setQuotaErr() {
	p.mu.Lock()
	p.quotaUntil = time.Now().Add(5 * time.Minute)
	p.mu.Unlock()
}

func (p *Pool) Ask(ctx context.Context, req string) (string, error) {
	// try up to 2 times
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		w, err := p.get()
		if err != nil {
			if err.Error() == "RESOURCE_EXHAUSTED" {
				return "", err
			}
			lastErr = err
			continue
		}

		ctxTimeout, cancel := context.WithTimeout(ctx, p.timeout)
		reply, err := w.Ask(ctxTimeout, req)
		cancel()

		if err != nil {
			if isQuota(err) {
				p.setQuotaErr()
				p.put(w, true)
				return "", errors.New("RESOURCE_EXHAUSTED")
			}
			p.put(w, true)
			lastErr = err
			continue
		}

		p.put(w, false)
		return reply, nil
	}
	return "", fmt.Errorf("all attempts failed, last err: %v", lastErr)
}
