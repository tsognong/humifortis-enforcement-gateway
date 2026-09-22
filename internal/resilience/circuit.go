package resilience

import (
	"errors"
	"sync"
	"time"
)

var ErrOpen = errors.New("circuit breaker is open")

type Circuit struct {
	mu        sync.Mutex
	failures  int
	threshold int
	openUntil time.Time
	cooldown  time.Duration
}

func NewCircuit(threshold int, cooldown time.Duration) *Circuit {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = 5 * time.Second
	}
	return &Circuit{threshold: threshold, cooldown: cooldown}
}
func (c *Circuit) Allow() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.openUntil.IsZero() {
		return true
	}
	if time.Now().After(c.openUntil) {
		c.openUntil = time.Time{}
		c.failures = 0
		return true
	}
	return false
}
func (c *Circuit) Success() { c.mu.Lock(); c.failures = 0; c.openUntil = time.Time{}; c.mu.Unlock() }
func (c *Circuit) Failure() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures++
	if c.failures >= c.threshold {
		c.openUntil = time.Now().Add(c.cooldown)
	}
}
