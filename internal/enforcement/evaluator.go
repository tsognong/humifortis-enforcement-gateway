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
	cacheTTL   time.Duration
}

func NewEvaluator(client *humifortis.Client, store state.Store, circuit *resilience.Circuit, policy config.FailPolicy, cacheTTL time.Duration) *Evaluator {
	return &Evaluator{client: client, store: store, circuit: circuit, failPolicy: policy, cacheTTL: cacheTTL}
}
func (e *Evaluator) Evaluate(ctx context.Context, input auth.Context) (Result, error) {
	key := input.TenantID + ":" + input.SessionID
	if input.SessionID == "" {
		key = input.TenantID + ":" + input.Subject
	}
	if constraint, err := e.store.Get(ctx, key); err == nil && constraint != nil {
		return Result{Action: constraint.Action, DecisionID: constraint.DecisionID, RequiredAssurance: constraint.RequiredAssurance, ChallengeID: constraint.ChallengeID}, nil
	}
	if !e.circuit.Allow() {
		return e.unavailable(), nil
	}
	decision, err := e.client.Evaluate(ctx, humifortis.Context{TenantID: input.TenantID, Subject: input.Subject, SessionID: input.SessionID, DeviceID: input.DeviceID, SourceIP: input.SourceIP, AuthMethod: input.AuthMethod, AuthAssurance: input.AuthAssurance})
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
	return result, nil
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
