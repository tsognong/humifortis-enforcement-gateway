package enforcement

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/auth"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/config"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/humifortis"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/resilience"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/state"
	"sync"
	"time"
)

type Result struct {
	Action             string
	DecisionID         string
	RequiredAssurance  string
	ChallengeID        string
	BackendUnavailable bool
}
type Evaluator struct {
	client     *humifortis.Client
	store      state.Store
	circuit    *resilience.Circuit
	failPolicy config.FailPolicy
	// agentFailPolicy is what a verified agent gets when Humifortis cannot decide (closed unless the operator says otherwise)
	agentFailPolicy config.FailPolicy
	cacheTTL        time.Duration
	cacheMu         sync.Mutex
	cache           map[string]cached
}

// cached is a decision of Humifortis kept for cacheTTL: an API client sends many requests in a second, and each one
// is not a new question. A constraint pushed by CAEP is checked before the cache and always wins.
type cached struct {
	result  Result
	expires time.Time
}

func NewEvaluator(client *humifortis.Client, store state.Store, circuit *resilience.Circuit, policy config.FailPolicy, cacheTTL time.Duration) *Evaluator {
	return &Evaluator{client: client, store: store, circuit: circuit, failPolicy: policy, agentFailPolicy: config.FailClosed, cacheTTL: cacheTTL, cache: map[string]cached{}}
}
func (e *Evaluator) Evaluate(ctx context.Context, input auth.Context) (Result, error) {
	key := input.TenantID + ":" + input.SessionID
	if input.SessionID == "" {
		key = input.TenantID + ":" + input.Subject
	}
	if constraint, err := e.store.Get(ctx, key); err == nil && constraint != nil {
		return Result{Action: constraint.Action, DecisionID: constraint.DecisionID, RequiredAssurance: constraint.RequiredAssurance, ChallengeID: constraint.ChallengeID}, nil
	}
	if input.SessionID != "" {
		if constraint, err := e.store.Get(ctx, input.TenantID+":"+input.Subject); err == nil && constraint != nil {
			return Result{Action: constraint.Action, DecisionID: constraint.DecisionID, RequiredAssurance: constraint.RequiredAssurance, ChallengeID: constraint.ChallengeID}, nil
		}
	}
	if r, ok := e.cachedResult(key); ok {
		return r, nil
	}
	if !e.circuit.Allow() {
		return e.unavailable(), nil
	}
	decision, err := e.client.Evaluate(ctx, humifortis.Context{TenantID: input.TenantID, Subject: input.Subject, SessionID: input.SessionID, DeviceID: input.DeviceID, SourceIP: input.SourceIP, AuthMethod: input.AuthMethod, AuthAssurance: input.AuthAssurance, Method: input.Method, Path: input.Path})
	if err != nil {
		e.circuit.Failure()
		return e.unavailable(), nil
	}
	e.circuit.Success()
	action := normalize(decision.Action)
	result := Result{Action: action, DecisionID: decision.DecisionID, RequiredAssurance: decision.RequiredAssurance}
	if result.Action == "CHALLENGE" {
		result.ChallengeID = newID("ch")
	}
	e.remember(key, result)
	return result, nil
}
func (e *Evaluator) cachedResult(key string) (Result, bool) {
	if e.cacheTTL <= 0 {
		return Result{}, false
	}
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	c, ok := e.cache[key]
	if !ok || time.Now().After(c.expires) {
		delete(e.cache, key)
		return Result{}, false
	}
	return c.result, true
}

func (e *Evaluator) remember(key string, r Result) {
	if e.cacheTTL <= 0 {
		return
	}
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	now := time.Now()
	if len(e.cache) > 10000 { // bounded: a flood of distinct sessions cannot grow it without limit
		for k, c := range e.cache {
			if now.After(c.expires) {
				delete(e.cache, k)
			}
		}
	}
	e.cache[key] = cached{result: r, expires: now.Add(e.cacheTTL)}
}

func (e *Evaluator) unavailable() Result {
	action := "ALLOW"
	if e.failPolicy == config.FailClosed {
		action = "BLOCK"
	}
	return Result{Action: action, BackendUnavailable: true}
}
func normalize(action string) string {
	switch action {
	case "ALLOW":
		return "ALLOW"
	case "BLOCK", "DENY":
		return "BLOCK"
	case "CHALLENGE", "STEP_UP", "REQUIRE_MFA", "REQUIRE_WEBAUTHN":
		return "CHALLENGE"
	default:
		return "CHALLENGE"
	}
}
func newID(prefix string) string {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(raw)
}
