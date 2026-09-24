package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tsognong/humifortis-enforcement-gateway/internal/auth"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/config"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/enforcement"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/events"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/humifortis"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/metrics"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/resilience"
	"github.com/tsognong/humifortis-enforcement-gateway/internal/state"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration failed", "error", err)
		os.Exit(1)
	}
	proxies, err := auth.ParseCIDRs(cfg.TrustedProxyCIDRs)
	if err != nil {
		slog.Error("trusted proxy configuration failed", "error", err)
		os.Exit(1)
	}
	store := state.Store(state.NewMemory())
	if cfg.RedisURL != "" {
		redisStore, redisErr := state.NewRedis(cfg.RedisURL, "humifortis:gateway:")
		if redisErr != nil {
			slog.Error("redis configuration failed", "error", redisErr)
			os.Exit(1)
		}
		store = redisStore
	}
	client := humifortis.NewClient(cfg.HumifortisURL, cfg.HumifortisAPIKey, cfg.HumifortisTimeout)
	evaluator := enforcement.NewEvaluator(client, store, resilience.NewCircuit(5, 5*time.Second), cfg.FailPolicy, cfg.DecisionCacheTTL)
	metricsCollector := &metrics.Metrics{}
	publicKey, keyErr := loadPublicKey(cfg)
	if keyErr != nil && (cfg.CAEPPublicKeyPEM != "" || cfg.CAEPJWKSURL != "") {
		slog.Error("CAEP public key invalid", "error", keyErr)
		os.Exit(1)
	}
	receiver := events.NewReceiver(cfg, publicKey, store)
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", authHandler(evaluator, proxies, cfg, metricsCollector))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/ready", readyHandler(store, cfg))
	mux.HandleFunc("/metrics", metricsCollector.Handler)
	mux.HandleFunc("/ssf/caep/events", caepHandler(receiver, metricsCollector))
	server := &http.Server{Addr: ":" + cfg.Port, Handler: logging(mux), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		slog.Info("gateway_started", "port", cfg.Port, "humifortis_url", cfg.HumifortisURL)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("gateway_failed", "error", err)
			os.Exit(1)
		}
	}()
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func authHandler(evaluator *enforcement.Evaluator, proxies []*net.IPNet, cfg config.Config, m *metrics.Metrics) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.AuthRequests()
		input, err := auth.FromRequest(r, cfg.TrustedHeaderSecret, proxies)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid authorization context"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), cfg.HumifortisTimeout)
		defer cancel()
		result, _ := evaluator.Evaluate(ctx, input)
		switch result.Action {
		case "ALLOW":
			m.Allow()
			w.WriteHeader(http.StatusNoContent)
		case "BLOCK":
			m.Block()
			w.Header().Set("X-Humifortis-Decision", "BLOCK")
			w.Header().Set("X-Humifortis-Decision-ID", result.DecisionID)
			writeJSON(w, http.StatusForbidden, map[string]string{"decision": "BLOCK"})
		case "CHALLENGE":
			m.Challenge()
			w.Header().Set("X-Humifortis-Decision", "CHALLENGE")
			w.Header().Set("X-Humifortis-Decision-ID", result.DecisionID)
			w.Header().Set("X-Humifortis-Challenge-ID", result.ChallengeID)
			w.Header().Set("X-Humifortis-Required-Assurance", result.RequiredAssurance)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"decision": "CHALLENGE"})
		}
	}
}
func caepHandler(receiver *events.Receiver, m *metrics.Metrics) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		_, err = receiver.Process(string(raw))
		if err != nil {
			slog.Warn("caep_event_rejected", "error", err.Error())
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		m.CAEP()
		w.WriteHeader(http.StatusNoContent)
	}
}
func readyHandler(store state.Store, cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := store.Ping(r.Context()); err != nil {
			writeJSON(w, 503, map[string]string{"status": "not_ready", "error": err.Error()})
			return
		}
		if cfg.HumifortisURL == "" {
			writeJSON(w, 503, map[string]string{"status": "not_ready"})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ready"})
	}
}
func loadPublicKey(cfg config.Config) (*rsa.PublicKey, error) {
	if cfg.CAEPPublicKeyPEM == "" && cfg.CAEPJWKSURL != "" {
		resp, err := http.Get(cfg.CAEPJWKSURL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var document struct {
			Keys []struct {
				Kty string          `json:"kty"`
				N   string          `json:"n"`
				E   json.RawMessage `json:"e"`
			} `json:"keys"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&document); err != nil {
			return nil, err
		}
		if len(document.Keys) == 0 || document.Keys[0].Kty != "RSA" {
			return nil, fmt.Errorf("JWKS contains no RSA key")
		}
		modulus, err := base64.RawURLEncoding.DecodeString(document.Keys[0].N)
		if err != nil {
			return nil, err
		}
		exponent, err := jwkExponent(document.Keys[0].E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}, nil
	}
	return parsePublicKey(cfg.CAEPPublicKeyPEM)
}

func jwkExponent(raw json.RawMessage) (int, error) {
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err == nil {
		value, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(value) == 0 {
			return 0, fmt.Errorf("invalid JWKS RSA exponent")
		}
		exponent := 0
		for _, byteValue := range value {
			exponent = exponent<<8 | int(byteValue)
		}
		return exponent, nil
	}
	var numeric int
	if err := json.Unmarshal(raw, &numeric); err != nil {
		return 0, fmt.Errorf("invalid JWKS RSA exponent: %w", err)
	}
	return numeric, nil
}

func parsePublicKey(raw string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("PEM block missing")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if parsed, e := x509.ParsePKCS1PublicKey(block.Bytes); e == nil {
			return parsed, nil
		}
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}
	return rsaKey, nil
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		slog.Info("http_request", "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(started).Milliseconds())
	})
}
