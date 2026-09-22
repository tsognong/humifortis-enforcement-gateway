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
	Seen(context.Context, string, time.Duration) (bool, error)
	MarkSeen(context.Context, string, time.Duration) error
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
func (m *Memory) Seen(_ context.Context, key string, _ time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	expiry, ok := m.replay[key]
	return ok && time.Now().Before(expiry), nil
}
func (m *Memory) MarkSeen(_ context.Context, key string, ttl time.Duration) error {
	m.mu.Lock()
	m.replay[key] = time.Now().Add(ttl)
	m.mu.Unlock()
	return nil
}
func (m *Memory) Ping(context.Context) error { return nil }
