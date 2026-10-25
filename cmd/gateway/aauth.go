package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/tsognong/humifortis-enforcement-gateway/internal/aauth"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/auth"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/config"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/enforcement"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/humifortis"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/metrics"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/state"
)

// agentAuth is the AAuth path of /auth: verify the agent's proof, then ask Humifortis to decide the verified agent.
type agentAuth struct {
	cfg       config.Config
	verifier  *aauth.Verifier
	providers *humifortis.Providers
	reporter  *humifortis.Reporter
	metrics   *metrics.Metrics
	instance  string
}

// newAgentAuth builds the AAuth path, or returns nil when AAuth is not enabled.
func newAgentAuth(ctx context.Context, cfg config.Config, client *humifortis.Client, store state.Store, m *metrics.Metrics) (*agentAuth, error) {
	if !cfg.AAuthEnabled {
		return nil, nil
	}
	providers := humifortis.NewProviders(cfg.HumifortisURL, cfg.HumifortisAPIKey, cfg.HumifortisTimeout*20, cfg.AAuthProvidersMaxStale)
	if err := providers.Refresh(ctx); err != nil {
		// not fatal: nothing is trusted until Humifortis answers, which is the safe state
		slog.Warn("aauth_providers_unavailable", "error", err.Error())
	}
	go providers.Run(ctx, cfg.AAuthProvidersRefresh, func(err error) { slog.Warn("aauth_providers_refresh_failed", "error", err.Error()) })

	opt := aauth.DirectoryOptions{AllowPrivateNetworks: cfg.AAuthAllowPrivateNetworks}
	if cfg.AAuthRootCAsFile != "" {
		pem, err := os.ReadFile(cfg.AAuthRootCAsFile)
		if err != nil {
			return nil, fmt.Errorf("AAUTH_ROOT_CAS_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("AAUTH_ROOT_CAS_FILE holds no certificate")
		}
		opt.RootCAs = pool
	}
	verifier, err := aauth.NewVerifier(aauth.Config{TenantID: cfg.AAuthTenantID, Window: cfg.AAuthWindow}, providers, aauth.NewHTTPDirectory(opt), store, nil)
	if err != nil {
		return nil, err
	}
	reporter := humifortis.NewReporter(client, 30*time.Second)
	go reporter.Run(ctx)
	host, _ := os.Hostname()
	slog.Info("aauth_enabled", "tenant", cfg.AAuthTenantID, "window", cfg.AAuthWindow.String(), "fail_policy", string(cfg.AAuthFailPolicy))
	return &agentAuth{cfg: cfg, verifier: verifier, providers: providers, reporter: reporter, metrics: m, instance: host}, nil
}

func (a *agentAuth) handle(w http.ResponseWriter, r *http.Request, evaluator *enforcement.Evaluator, proxies []*net.IPNet) {
	req, ip, err := auth.AAuthRequest(r, proxies)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid authorization context"})
		return
	}
	verified, verr := a.verifier.Verify(r.Context(), req)
	if verr != nil {
		a.refuse(w, verr, ip)
		return
	}
	answer := evaluator.EvaluateAgent(r.Context(), enforcement.AgentContext{
		Verified: verified, TenantID: a.cfg.AAuthTenantID, Method: req.Method, Path: req.Path, Authority: req.Authority, SourceIP: ip, Instance: a.instance,
	})
	w.Header().Set("X-Humifortis-Decision-ID", answer.DecisionID)
	if answer.Status == http.StatusNoContent {
		a.metrics.AgentAllowed()
		w.Header().Set("X-Humifortis-Decision", "ALLOW")
		w.Header().Set("X-Agent-Id", verified.AgentID)
		w.Header().Set("X-Agent-Issuer", verified.Issuer)
		w.Header().Set("X-Agent-Key-Jkt", verified.JKT)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// a refusal after a successful verification carries no Signature-Error and no AAuth-Requirement (the proof was fine)
	a.metrics.AgentRefused()
	w.Header().Set("X-Humifortis-Decision", answer.Decision)
	writeJSON(w, answer.Status, map[string]string{"decision": answer.Decision, "reason": answer.Reason})
}

// refuse answers a request whose proof failed. The client is told the verdict, never the tenant's configuration; Humifortis is
// told as a fact about the integration, and the refusal never waits for that.
func (a *agentAuth) refuse(w http.ResponseWriter, verr *aauth.Error, ip string) {
	a.metrics.AgentProofRejected()
	declared := verr.Issuer != "" && a.providers.Declared(verr.Issuer)
	issuer := ""
	if declared {
		issuer = verr.Issuer
	}
	a.reporter.Report(humifortis.ProofRejected{Issuer: issuer, Code: string(verr.Code), Reason: string(verr.Reason), SourceIP: ip})
	if h := verr.SignatureError(); h != "" {
		w.Header().Set("Signature-Error", h)
	}
	slog.Warn("aauth_proof_rejected", "code", string(verr.Code), "reason", string(verr.Reason), "detail", verr.Detail, "issuer", issuer)
	writeJSON(w, verr.Status(), map[string]string{"error": string(verr.Code)})
}
