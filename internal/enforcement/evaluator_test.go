package enforcement

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tsognong/humifortis-enforcement-gateway/internal/auth"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/config"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/humifortis"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/resilience"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/state"
)

func TestEvaluatorMapsStepUpToChallenge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"STEP_UP","decision_id":"dec-1","required_assurance":"MFA"}`))
	}))
	defer server.Close()
	evaluator := NewEvaluator(humifortis.NewClient(server.URL, "", time.Second), state.NewMemory(), resilience.NewCircuit(2, time.Second), config.FailClosed, time.Second)
	result, err := evaluator.Evaluate(context.Background(), auth.Context{TenantID: "tenant-a", Subject: "user-a"})
	if err != nil || result.Action != "CHALLENGE" || result.DecisionID != "dec-1" || result.RequiredAssurance != "MFA" {
		t.Fatalf("unexpected result=%+v err=%v", result, err)
	}
}

func TestEvaluatorFailsClosedWhenCoreUnavailable(t *testing.T) {
	evaluator := NewEvaluator(humifortis.NewClient("http://127.0.0.1:1", "", 10*time.Millisecond), state.NewMemory(), resilience.NewCircuit(1, time.Second), config.FailClosed, time.Second)
	result, err := evaluator.Evaluate(context.Background(), auth.Context{TenantID: "tenant-a", Subject: "user-a"})
	if err != nil || result.Action != "BLOCK" || !result.BackendUnavailable {
		t.Fatalf("expected fail-closed block, result=%+v err=%v", result, err)
	}
}
