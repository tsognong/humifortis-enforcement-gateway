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
}
type Decision struct {
	Action            string `json:"action"`
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
	body := map[string]any{"event": map[string]any{"entity_id": input.Subject, "entity_type": "user", "event_type": "auth_login_success", "source": "enforcement-gateway", "metadata": input}, "available_methods": []string{input.AuthAssurance}}
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
