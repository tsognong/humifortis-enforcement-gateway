package enforcement

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tsognong/humifortis-enforcement-gateway/internal/aauth"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/config"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/humifortis"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/resilience"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/state"
)

func TestMapAgentActionIsClosed(t *testing.T) {
	cases := []struct {
		enforced, action string
		status           int
		reason           string
	}{
		{"ALLOW", "", 204, ""},
		{"", "ALLOW", 204, ""},
		{"DENY", "ALLOW", 403, "denied"},
		{"", "DENY", 403, "denied"},
		{"DISABLE_CLIENT", "", 403, "agent_suspended"},
		{"", "REQUIRE_MFA", 403, "step_up_not_supported_for_agent"},
		{"", "STEP_UP", 403, "step_up_not_supported_for_agent"},
		{"", "CHALLENGE", 403, "step_up_not_supported_for_agent"},
		{"", "", 403, "unmappable_action"},
		{"", "SOMETHING_NEW", 403, "unmappable_action"},
	}
	for _, c := range cases {
		got := MapAgentAction(c.enforced, c.action)
		if got.Status != c.status || got.Reason != c.reason {
			t.Errorf("%q/%q: %+v", c.enforced, c.action, got)
		}
	}
}

func verified() *aauth.Verified {
	return &aauth.Verified{
		AgentID: "agent:aauth:planner@agents.example.com", Issuer: "agents.example.com", Trust: "enterprise", JKT: "thumb", KeyAlg: "EdDSA",
		TokenID: "jti-1", TokenIssuedAt: time.Unix(1000, 0), TokenExpiresAt: time.Unix(4600, 0), TokenFresh: true, SignatureCreated: time.Unix(1100, 0),
		Covered: []string{"@method", "@authority", "@path", "signature-key"},
	}
}

func TestEvaluateAgentSendsOnlyVerifiedFactsAndDeclaresExecutors(t *testing.T) {
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"action":"ALLOW","enforced_action":"ALLOW","decision_id":"dec-9"}`))
	}))
	defer server.Close()
	ev := NewEvaluator(humifortis.NewClient(server.URL, "", time.Second), state.NewMemory(), resilience.NewCircuit(2, time.Second), config.FailOpen, 0)
	ans := ev.EvaluateAgent(context.Background(), AgentContext{Verified: verified(), TenantID: "t1", Method: "GET", Path: "/orders", Authority: "api.example.com", SourceIP: "203.0.113.7"})
	if ans.Status != 204 || ans.DecisionID != "dec-9" {
		t.Fatalf("answer: %+v", ans)
	}
	event := body["event"].(map[string]any)
	if event["entity_id"] != "agent:aauth:planner@agents.example.com" || event["event_type"] != "api_call" {
		t.Fatalf("event: %v", event)
	}
	if _, has := event["entity_type"]; has {
		t.Fatal("the gateway never sends a type: the registered prefix of the id is the authority")
	}
	md := event["metadata"].(map[string]any)
	for _, k := range []string{"aauth.issuer", "aauth.key_thumbprint", "aauth.token_fresh", "aauth.issuer_trust", "device_id"} {
		if _, ok := md[k]; !ok {
			t.Errorf("metadata lacks %s", k)
		}
	}
	if md["device_id"] != "jkt:thumb" || md["auth_method"] != "aauth" {
		t.Fatalf("metadata: %v", md)
	}
	if _, has := md["proof.verified"]; has {
		t.Fatal("proof.verified is stamped by Core from the key's scope, never sent")
	}
	ex := body["executors"].([]any)
	if len(ex) != 2 {
		t.Fatalf("executors: %v", ex)
	}
}

func TestEvaluateAgentRefusesWhenCoreIsDownUnlessTheOperatorSaidOtherwise(t *testing.T) {
	down := func(p config.FailPolicy) AgentAnswer {
		ev := NewEvaluator(humifortis.NewClient("http://127.0.0.1:1", "", 10*time.Millisecond), state.NewMemory(), resilience.NewCircuit(1, time.Second), config.FailOpen, 0).WithAgentFailPolicy(p)
		return ev.EvaluateAgent(context.Background(), AgentContext{Verified: verified(), TenantID: "t1"})
	}
	if a := down(config.FailClosed); a.Status != 403 || a.Reason != "humifortis_unavailable" {
		t.Fatalf("closed: %+v", a)
	}
	// the person path's fail-open does not leak into the agent path
	ev := NewEvaluator(humifortis.NewClient("http://127.0.0.1:1", "", 10*time.Millisecond), state.NewMemory(), resilience.NewCircuit(1, time.Second), config.FailOpen, 0)
	if a := ev.EvaluateAgent(context.Background(), AgentContext{Verified: verified(), TenantID: "t1"}); a.Status != 403 {
		t.Fatalf("the default of the agent path is closed even when the person path is open: %+v", a)
	}
	if a := down(config.FailOpen); a.Status != 204 {
		t.Fatalf("explicit fail_open: %+v", a)
	}
}

func TestEvaluateAgentCachesAnAllowOnly(t *testing.T) {
	calls := 0
	action := "ALLOW"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"action":"` + action + `","enforced_action":"` + action + `","decision_id":"d"}`))
	}))
	defer server.Close()
	ev := NewEvaluator(humifortis.NewClient(server.URL, "", time.Second), state.NewMemory(), resilience.NewCircuit(2, time.Second), config.FailClosed, time.Minute)
	in := AgentContext{Verified: verified(), TenantID: "t1"}
	ev.EvaluateAgent(context.Background(), in)
	ev.EvaluateAgent(context.Background(), in)
	if calls != 1 {
		t.Fatalf("an ALLOW is cached for the window, calls=%d", calls)
	}
	other := verified()
	other.AgentID = "agent:aauth:other@agents.example.com"
	action = "DENY"
	if a := ev.EvaluateAgent(context.Background(), AgentContext{Verified: other, TenantID: "t1"}); a.Status != 403 {
		t.Fatalf("a deny is a deny: %+v", a)
	}
	ev.EvaluateAgent(context.Background(), AgentContext{Verified: other, TenantID: "t1"})
	if calls != 3 {
		t.Fatalf("a DENY is never cached, calls=%d", calls)
	}
	if a := ev.EvaluateAgent(context.Background(), AgentContext{Verified: verified(), TenantID: "t2"}); calls != 4 || a.Status != 403 {
		t.Fatalf("the cache is per tenant, calls=%d %+v", calls, a)
	}
}
