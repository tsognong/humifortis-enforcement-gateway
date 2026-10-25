package enforcement

import (
	"context"
	"encoding/json"
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

func TestEvaluatorReportsAnApiCall_neverALogin(t *testing.T) {
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"action":"ALLOW","decision_id":"d"}`))
	}))
	defer server.Close()
	evaluator := NewEvaluator(humifortis.NewClient(server.URL, "", time.Second), state.NewMemory(), resilience.NewCircuit(2, time.Second), config.FailClosed, 0)
	_, err := evaluator.Evaluate(context.Background(), auth.Context{TenantID: "t", Subject: "u", Method: "GET", Path: "/orders"})
	if err != nil {
		t.Fatal(err)
	}
	event, _ := body["event"].(map[string]any)
	if event["event_type"] != "api_call" || event["source"] != "enforcement-gateway" {
		t.Fatalf("the gateway must report an api_call, got %v", event)
	}
	md, _ := event["metadata"].(map[string]any)
	if md["http_method"] != "GET" || md["http_path"] != "/orders" {
		t.Fatalf("the request being authorised travels with the event, got %v", md)
	}
}

func TestEvaluatorCachesADecisionForTheTTL(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"action":"ALLOW","decision_id":"d"}`))
	}))
	defer server.Close()
	evaluator := NewEvaluator(humifortis.NewClient(server.URL, "", time.Second), state.NewMemory(), resilience.NewCircuit(2, time.Second), config.FailClosed, 200*time.Millisecond)
	in := auth.Context{TenantID: "t", Subject: "u", SessionID: "s1"}
	for i := 0; i < 5; i++ {
		if r, _ := evaluator.Evaluate(context.Background(), in); r.Action != "ALLOW" {
			t.Fatalf("request %d: %+v", i, r)
		}
	}
	if calls != 1 {
		t.Fatalf("five requests of one session within the TTL are one question to Humifortis, got %d", calls)
	}
	if _, _ = evaluator.Evaluate(context.Background(), auth.Context{TenantID: "t", Subject: "u", SessionID: "s2"}); calls != 2 {
		t.Fatalf("another session is another question, got %d calls", calls)
	}
	time.Sleep(250 * time.Millisecond)
	_, _ = evaluator.Evaluate(context.Background(), in)
	if calls != 3 {
		t.Fatalf("after the TTL the question is asked again, got %d calls", calls)
	}
}

func TestACaepConstraintWinsOverTheCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"action":"ALLOW","decision_id":"d"}`))
	}))
	defer server.Close()
	store := state.NewMemory()
	evaluator := NewEvaluator(humifortis.NewClient(server.URL, "", time.Second), store, resilience.NewCircuit(2, time.Second), config.FailClosed, time.Minute)
	in := auth.Context{TenantID: "t", Subject: "u", SessionID: "s1"}
	if r, _ := evaluator.Evaluate(context.Background(), in); r.Action != "ALLOW" {
		t.Fatalf("first decision: %+v", r)
	}
	_ = store.Put(context.Background(), "t:s1", state.Constraint{Action: "BLOCK", DecisionID: "caep-1", ExpiresAt: time.Now().Add(time.Minute)})
	if r, _ := evaluator.Evaluate(context.Background(), in); r.Action != "BLOCK" || r.DecisionID != "caep-1" {
		t.Fatalf("a pushed constraint must win over a cached ALLOW, got %+v", r)
	}
}
