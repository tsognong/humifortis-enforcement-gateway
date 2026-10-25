package humifortis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Context struct {
	TenantID      string `json:"tenant_id"`
	Subject       string `json:"entity_id"`
	SessionID     string `json:"session_id,omitempty"`
	DeviceID      string `json:"device_id,omitempty"`
	SourceIP      string `json:"source_ip,omitempty"`
	AuthMethod    string `json:"auth_method,omitempty"`
	AuthAssurance string `json:"auth_assurance,omitempty"`
	Method        string `json:"http_method,omitempty"`
	Path          string `json:"http_path,omitempty"`
}
type Decision struct {
	Action string `json:"action"`
	// EnforcedAction is what the caller must do, given the executors it declared (the agent path reads it first).
	EnforcedAction    string `json:"enforced_action,omitempty"`
	DecisionID        string `json:"decision_id,omitempty"`
	RiskLevel         string `json:"risk_level,omitempty"`
	RequiredAssurance string `json:"required_assurance,omitempty"`
}
type Client struct {
	base string
	key  string
	http *http.Client
}

func NewClient(base, key string, timeout time.Duration) *Client {
	return &Client{base: strings.TrimRight(base, "/"), key: key, http: &http.Client{Timeout: timeout}}
}
func (c *Client) Evaluate(ctx context.Context, input Context) (Decision, error) {
	body := map[string]any{"event": map[string]any{"entity_id": input.Subject, "entity_type": "user", "event_type": "api_call", "source": "enforcement-gateway", "metadata": input}, "available_methods": []string{input.AuthAssurance}}
	encoded, err := json.Marshal(body)
	if err != nil {
		return Decision{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/evaluate", bytes.NewReader(encoded))
	if err != nil {
		return Decision{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.key != "" {
		req.Header.Set("X-API-Key", c.key)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Decision{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Decision{}, fmt.Errorf("humifortis returned status %d", resp.StatusCode)
	}
	var result Decision
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return Decision{}, err
	}
	return result, nil
}

// AgentRequest is a request whose agent identity the gateway verified (internal/aauth). The metadata carries only what the verifier
// checked or derived; nothing the client merely claimed (docs/aauth-agent.spec.md, 6.1). No entity_type: the registered
// prefix of the id says it is an agent, and Core's registry is the authority.
type AgentRequest struct {
	AgentID  string
	Metadata map[string]any
	// Executors are the actions the gateway can carry out for this request.
	Executors []string
}

// EvaluateAgent asks Humifortis to decide a verified agent's request.
func (c *Client) EvaluateAgent(ctx context.Context, in AgentRequest) (Decision, error) {
	body := map[string]any{
		"event":     map[string]any{"entity_id": in.AgentID, "event_type": "api_call", "source": "enforcement-gateway", "metadata": in.Metadata},
		"executors": in.Executors,
	}
	var out Decision
	if err := c.post(ctx, "/evaluate", body, &out); err != nil {
		return Decision{}, err
	}
	return out, nil
}

// ProofRejected is a request whose AAuth proof the gateway refused. It names no agent: the proof is what failed.
type ProofRejected struct {
	// Issuer is the claimed provider, sent only when the tenant declared it (Core uses it in an alert, never as an entity).
	Issuer string
	// Code is the verifier's closed taxonomy (invalid_signature, unknown_issuer...).
	Code, Reason string
	SourceIP     string
}

// ReportProofRejected sends the feedback event; the refusal never waits for it.
func (c *Client) ReportProofRejected(ctx context.Context, in ProofRejected) error {
	body := map[string]any{"event": map[string]any{
		"entity_id": "integration:enforcement-gateway", "event_type": "aauth_proof_rejected", "source": "enforcement-gateway",
		"metadata": map[string]any{"issuer": in.Issuer, "failure_code": in.Code, "reason": in.Reason, "source_ip": in.SourceIP},
	}}
	return c.post(ctx, "/events", body, nil)
}

func (c *Client) post(ctx context.Context, path string, body any, out any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.key != "" {
		req.Header.Set("X-API-Key", c.key)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("humifortis returned status %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
