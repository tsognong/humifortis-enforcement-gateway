package state

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type Constraint struct {
	TenantID          string    `json:"tenant_id"`
	Subject           string    `json:"subject"`
	SessionID         string    `json:"session_id,omitempty"`
	Action            string    `json:"constraint"`
	DecisionID        string    `json:"decision_id"`
	ChallengeID       string    `json:"challenge_id,omitempty"`
	RequiredAssurance string    `json:"required_assurance,omitempty"`
	ExpiresAt         time.Time `json:"expires_at"`
}
type Store interface {
	Get(context.Context, string) (*Constraint, error)
	Put(context.Context, string, Constraint) error
	Delete(context.Context, string) error
	// FirstUse marks the key for ttl and reports whether it had not been marked: ONE atomic operation, so two requests (or
	// two gateway instances) racing on the same replay key cannot both be the first.
	FirstUse(context.Context, string, time.Duration) (bool, error)
	Ping(context.Context) error
}
type Memory struct {
	mu     sync.Mutex
	values map[string]Constraint
	replay map[string]time.Time
}

func NewMemory() *Memory {
	return &Memory{values: map[string]Constraint{}, replay: map[string]time.Time{}}
}
func (m *Memory) Get(_ context.Context, key string) (*Constraint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.values[key]
	if !ok || time.Now().After(value.ExpiresAt) {
		delete(m.values, key)
		return nil, nil
	}
	copy := value
	return &copy, nil
}
func (m *Memory) Put(_ context.Context, key string, value Constraint) error {
	if value.ExpiresAt.IsZero() {
		return fmt.Errorf("constraint expiry is required")
	}
	m.mu.Lock()
	m.values[key] = value
	m.mu.Unlock()
	return nil
}
func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	delete(m.values, key)
	m.mu.Unlock()
	return nil
}
func (m *Memory) FirstUse(_ context.Context, key string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if expiry, ok := m.replay[key]; ok && now.Before(expiry) {
		return false, nil
	}
	if len(m.replay) > 100000 { // bounded: a flood of distinct keys cannot grow it without limit
		for k, e := range m.replay {
			if now.After(e) {
				delete(m.replay, k)
			}
		}
	}
	m.replay[key] = now.Add(ttl)
	return true, nil
}
func (m *Memory) Ping(context.Context) error { return nil }
