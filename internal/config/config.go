package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type FailPolicy string

const (
	FailOpen   FailPolicy = "fail_open"
	FailClosed FailPolicy = "fail_closed"
)

type Config struct {
	Port                string
	HumifortisURL       string
	HumifortisAPIKey    string
	HumifortisTimeout   time.Duration
	FailPolicy          FailPolicy
	RedisURL            string
	StateTTL            time.Duration
	DecisionCacheTTL    time.Duration
	TrustedHeaderSecret string
	TrustedProxyCIDRs   []string
	CAEPIssuer          string
	CAEPAudience        string
	CAEPTenantID        string
	CAEPPublicKeyPEM    string
	CAEPClockSkew       time.Duration
	ReplayTTL           time.Duration
}

func Load() (Config, error) {
	c := Config{
		Port:                env("PORT", "8081"),
		HumifortisURL:       strings.TrimRight(env("HUMIFORTIS_URL", "http://localhost:8080/api/v1"), "/"),
		HumifortisAPIKey:    os.Getenv("HUMIFORTIS_API_KEY"),
		FailPolicy:          FailPolicy(env("HUMIFORTIS_FAIL_POLICY", string(FailClosed))),
		RedisURL:            os.Getenv("REDIS_URL"),
		TrustedHeaderSecret: os.Getenv("GATEWAY_TRUSTED_HEADER_SECRET"),
		CAEPIssuer:          os.Getenv("CAEP_ISSUER"),
		CAEPAudience:        env("CAEP_AUDIENCE", "humifortis-enforcement-gateway"),
		CAEPPublicKeyPEM:    os.Getenv("CAEP_PUBLIC_KEY_PEM"),
		CAEPTenantID:        os.Getenv("CAEP_TENANT_ID"),
		TrustedProxyCIDRs:   split(env("GATEWAY_TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128")),
	}
	var err error
	if c.HumifortisTimeout, err = duration("HUMIFORTIS_TIMEOUT", 100*time.Millisecond); err != nil {
		return Config{}, err
	}
	if c.StateTTL, err = duration("STATE_TTL", 5*time.Minute); err != nil {
		return Config{}, err
	}
	if c.DecisionCacheTTL, err = duration("DECISION_CACHE_TTL", 5*time.Second); err != nil {
		return Config{}, err
	}
	if c.CAEPClockSkew, err = duration("CAEP_CLOCK_SKEW", 30*time.Second); err != nil {
		return Config{}, err
	}
	if c.ReplayTTL, err = duration("REPLAY_TTL", 5*time.Minute); err != nil {
		return Config{}, err
	}
	if c.FailPolicy != FailOpen && c.FailPolicy != FailClosed {
		return Config{}, fmt.Errorf("HUMIFORTIS_FAIL_POLICY must be fail_open or fail_closed")
	}
	return c, nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func split(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
func duration(key string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be positive", key)
	}
	return parsed, nil
}
