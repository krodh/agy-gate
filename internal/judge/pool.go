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

func (p *Pool) startOne() {
	// Spawn and warmup
	w, err := StartWorker(context.Background(), p.cfg)
	if err != nil {
		// Log error? We don't have a logger, just sleep and retry
		time.Sleep(2 * time.Second)
		go p.startOne()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	// Warmup with throwaway
	_, _ = w.Ask(ctx, "warmup")

	p.workers <- w
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
			msg := err.Error()
			if strings.Contains(msg, "quota") || strings.Contains(msg, "RESOURCE_EXHAUSTED") || strings.Contains(msg, "429") {
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
