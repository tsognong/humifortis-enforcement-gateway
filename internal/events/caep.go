package events

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/config"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/state"
	"strings"
	"time"
)

type Receiver struct {
	cfg   config.Config
	key   *rsa.PublicKey
	store state.Store
}
type setClaims struct {
	Events map[string]map[string]any `json:"events"`
	SubID  map[string]string         `json:"sub_id"`
	jwt.RegisteredClaims
}

func NewReceiver(cfg config.Config, key *rsa.PublicKey, store state.Store) *Receiver {
	return &Receiver{cfg: cfg, key: key, store: store}
}
func (r *Receiver) Process(raw string) (state.Constraint, error) {
	if r.key == nil {
		return state.Constraint{}, fmt.Errorf("CAEP public key is not configured")
	}
	token, err := jwt.ParseWithClaims(raw, &setClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unsupported signing algorithm")
		}
		return r.key, nil
	}, jwt.WithAudience(r.cfg.CAEPAudience))
	if err != nil || !token.Valid {
		return state.Constraint{}, fmt.Errorf("invalid signed event")
	}
	claims, ok := token.Claims.(*setClaims)
	if !ok {
		return state.Constraint{}, fmt.Errorf("claims type invalid")
	}
	if claims.Issuer != r.cfg.CAEPIssuer {
		return state.Constraint{}, fmt.Errorf("issuer mismatch: got %q want %q", claims.Issuer, r.cfg.CAEPIssuer)
	}
	if claims.ID == "" {
		return state.Constraint{}, fmt.Errorf("jti missing")
	}
	if claims.IssuedAt == nil || time.Since(claims.IssuedAt.Time) > r.cfg.CAEPClockSkew+5*time.Minute {
		return state.Constraint{}, fmt.Errorf("event outside replay window")
	}
	seen, err := r.store.Seen(context.Background(), claims.ID, r.cfg.ReplayTTL)
	if err != nil {
		return state.Constraint{}, err
	}
	if seen {
		return state.Constraint{}, fmt.Errorf("replay detected")
	}
	if err := r.store.MarkSeen(context.Background(), claims.ID, r.cfg.ReplayTTL); err != nil {
		return state.Constraint{}, err
	}
	subject := claims.SubID["sub"]
	if subject == "" {
		return state.Constraint{}, fmt.Errorf("subject is required")
	}
	event, ok := claims.Events["https://schemas.openid.net/secevent/caep/event-type/risk-level-change"]
	if !ok {
		return state.Constraint{}, fmt.Errorf("unsupported CAEP event")
	}
	level, _ := event["current_level"].(string)
	action := "CHALLENGE"
	if strings.EqualFold(level, "high") || strings.EqualFold(level, "critical") {
		action = "BLOCK"
	}
	constraint := state.Constraint{TenantID: r.cfg.CAEPTenantID, Subject: subject, SessionID: subject, Action: action, DecisionID: claims.ID, ChallengeID: "challenge-" + claims.ID, RequiredAssurance: "MFA", ExpiresAt: time.Now().Add(r.cfg.StateTTL)}
	if err := r.store.Put(context.Background(), r.cfg.CAEPTenantID+":"+subject, constraint); err != nil {
		return state.Constraint{}, err
	}
	return constraint, nil
}

var _ = json.Valid
