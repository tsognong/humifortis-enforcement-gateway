package enforcement

import (
	"context"
	"net/http"
	"strings"

	"github.com/tsognong/humifortis-enforcement-gateway/internal/aauth"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/config"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/humifortis"
)

// AgentExecutors are the actions the gateway carries out for a verified agent. It declares them to Core, which then returns each
// as enforced rather than advisory: a decision the gateway cannot execute is never presented as done.
var AgentExecutors = []string{"DENY", "DISABLE_CLIENT"}

// AgentAnswer is the gateway's answer to nginx for a verified agent: a closed mapping (docs/aauth-agent.spec.md, 10.2). Anything
// that is not known to be an allowance is a refusal: a machine has nobody to challenge, and the default of the person path
// (a challenge) would be answered by an agent with nothing.
type AgentAnswer struct {
	Status     int // 204 allow, 403 refuse
	Decision   string
	DecisionID string
	Reason     string
}

// MapAgentAction maps what Core decided. enforced_action wins over action.
func MapAgentAction(enforced, action string) AgentAnswer {
	a := strings.ToUpper(strings.TrimSpace(enforced))
	if a == "" {
		a = strings.ToUpper(strings.TrimSpace(action))
	}
	switch a {
	case "ALLOW":
		return AgentAnswer{Status: http.StatusNoContent, Decision: "ALLOW"}
	case "DENY", "BLOCK":
		return AgentAnswer{Status: http.StatusForbidden, Decision: "BLOCK", Reason: "denied"}
	case "DISABLE_CLIENT":
		return AgentAnswer{Status: http.StatusForbidden, Decision: "BLOCK", Reason: "agent_suspended"}
	case "REQUIRE_MFA", "REQUIRE_WEBAUTHN", "STEP_UP", "CHALLENGE":
		// an agent cannot complete a person's step-up: denied, never allowed and never turned into a Bearer challenge
		return AgentAnswer{Status: http.StatusForbidden, Decision: "BLOCK", Reason: "step_up_not_supported_for_agent"}
	default:
		return AgentAnswer{Status: http.StatusForbidden, Decision: "BLOCK", Reason: "unmappable_action"}
	}
}

// AgentContext is a request whose agent identity was verified.
type AgentContext struct {
	Verified *aauth.Verified
	TenantID string
	Method   string
	Path     string
	// Authority is the Host the client signed (covered component).
	Authority string
	SourceIP  string
	Instance  string
}

// AgentMetadata is the metadata of the api_call event: every key is verified or derived (6.1); an asserted claim never travels
// under a verified name.
func AgentMetadata(in AgentContext) map[string]any {
	v := in.Verified
	m := map[string]any{
		"tenant_id":            in.TenantID,
		"auth_method":          "aauth",
		"device_id":            "jkt:" + v.JKT,
		"source_ip":            in.SourceIP,
		"http_method":          in.Method,
		"http_path":            in.Path,
		"http_authority":       in.Authority,
		"aauth.issuer":         v.Issuer,
		"aauth.issuer_trust":   v.Trust,
		"aauth.key_thumbprint": v.JKT,
		"aauth.key_alg":        v.KeyAlg,
		"aauth.token_jti":      v.TokenID,
		"aauth.token_iat":      v.TokenIssuedAt.Unix(),
		"aauth.token_exp":      v.TokenExpiresAt.Unix(),
		"aauth.token_fresh":    v.TokenFresh,
		"aauth.sig_created":    v.SignatureCreated.Unix(),
		"aauth.sig_covered":    v.Covered,
		"aauth.replay_checked": true,
		"aauth.profile":        "AAUTH-H1",
		"gateway.instance":     in.Instance,
	}
	if v.ParentAgent != "" {
		m["aauth.parent_agent"] = v.ParentAgent
	}
	if v.PS != "" {
		m["aauth.ps"] = v.PS
	}
	return m
}

// EvaluateAgent decides a verified agent's request. A constraint pushed by CAEP is not consulted (it is keyed by a person's
// session); the decision cache keeps ALLOW only for a short while, like the person path. Core unreachable gives the AAuth
// fail policy, closed by default.
func (e *Evaluator) EvaluateAgent(ctx context.Context, in AgentContext) AgentAnswer {
	key := "agent:" + in.TenantID + ":" + in.Verified.AgentID
	if r, ok := e.cachedResult(key); ok && r.Action == "ALLOW" {
		return AgentAnswer{Status: http.StatusNoContent, Decision: "ALLOW", DecisionID: r.DecisionID}
	}
	if !e.circuit.Allow() {
		return e.agentUnavailable(key)
	}
	d, err := e.client.EvaluateAgent(ctx, humifortis.AgentRequest{AgentID: in.Verified.AgentID, Metadata: AgentMetadata(in), Executors: AgentExecutors})
	if err != nil {
		e.circuit.Failure()
		return e.agentUnavailable(key)
	}
	e.circuit.Success()
	a := MapAgentAction(d.EnforcedAction, d.Action)
	a.DecisionID = d.DecisionID
	if a.Status == http.StatusNoContent {
		e.remember(key, Result{Action: "ALLOW", DecisionID: d.DecisionID})
	}
	return a
}

// agentUnavailable: Humifortis cannot decide. Closed by default; open only for an agent that was allowed within the cache window
// (the cached ALLOW was handled before), never a blanket bypass.
func (e *Evaluator) agentUnavailable(string) AgentAnswer {
	if e.agentFailPolicy == config.FailOpen {
		return AgentAnswer{Status: http.StatusNoContent, Decision: "ALLOW", Reason: "humifortis_unavailable"}
	}
	return AgentAnswer{Status: http.StatusForbidden, Decision: "BLOCK", Reason: "humifortis_unavailable"}
}

// WithAgentFailPolicy sets what an agent request gets when Humifortis cannot decide.
func (e *Evaluator) WithAgentFailPolicy(p config.FailPolicy) *Evaluator {
	e.agentFailPolicy = p
	return e
}
