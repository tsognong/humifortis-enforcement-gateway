package humifortis

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Reporter sends the refused proofs to Humifortis without ever delaying the refusal: a bounded queue, one report per (issuer,
// code) in a window (a flood of identical failures is one fact with a count in the metrics), and a failed report is dropped
// after being counted (D7: the rejection never depends on its report).
type Reporter struct {
	client  *Client
	window  time.Duration
	queue   chan ProofRejected
	now     func() time.Time
	mu      sync.Mutex
	last    map[string]time.Time
	Dropped atomic.Int64
	Failed  atomic.Int64
	Sent    atomic.Int64
}

func NewReporter(c *Client, window time.Duration) *Reporter {
	return &Reporter{client: c, window: window, queue: make(chan ProofRejected, 256), now: time.Now, last: map[string]time.Time{}}
}

// Report queues the fact, or drops it (counted) when it is a repeat in the window or the queue is full.
func (r *Reporter) Report(p ProofRejected) {
	key := p.Issuer + "|" + p.Code
	r.mu.Lock()
	now := r.now()
	if t, ok := r.last[key]; ok && now.Sub(t) < r.window {
		r.mu.Unlock()
		r.Dropped.Add(1)
		return
	}
	if len(r.last) > 4096 { // bounded: names chosen by a stranger cannot grow it without limit
		for k, t := range r.last {
			if now.Sub(t) >= r.window {
				delete(r.last, k)
			}
		}
		if len(r.last) > 4096 {
			r.mu.Unlock()
			r.Dropped.Add(1)
			return
		}
	}
	r.last[key] = now
	r.mu.Unlock()
	select {
	case r.queue <- p:
	default:
		r.Dropped.Add(1)
	}
}

// Run sends the queued reports until ctx ends.
func (r *Reporter) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-r.queue:
			c, cancel := context.WithTimeout(ctx, 3*time.Second)
			if err := r.client.ReportProofRejected(c, p); err != nil {
				r.Failed.Add(1)
			} else {
				r.Sent.Add(1)
			}
			cancel()
		}
	}
}
