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
	CAEPJWKSURL         string
	CAEPPublicKeyPEM    string
	CAEPClockSkew       time.Duration
	ReplayTTL           time.Duration

	// AAuth: agents that prove their identity with an HTTP Message Signature (docs/aauth-agent.spec.md in humifortis-core).
	AAuthEnabled bool
	// AAuthTenantID is the tenant of every AAuth request: configuration, never a header of the client (D8).
	AAuthTenantID string
	// AAuthWindow is how far from now the created parameter of a signature may be.
	AAuthWindow time.Duration
	// AAuthProvidersRefresh is how often the tenant's agent providers are read from Humifortis; AAuthProvidersMaxStale how long the
	// last answer is used when Humifortis cannot be reached (then every provider is untrusted: fail closed).
	AAuthProvidersRefresh  time.Duration
	AAuthProvidersMaxStale time.Duration
	// AAuthFailPolicy: what an AAuth request gets when Humifortis cannot decide. The default is fail_closed: a machine has no
	// person to retry, and an open default would turn an outage into a bypass.
	AAuthFailPolicy FailPolicy
	// AAuthAllowPrivateNetworks lets the verifier fetch provider metadata from private addresses (a lab). Never in production.
	AAuthAllowPrivateNetworks bool
	// AAuthRootCAsFile is a PEM file of a private CA for provider metadata (a lab).
	AAuthRootCAsFile string
}

func Load() (Config, error) {
	c := Config{
		Port:                      env("PORT", "8081"),
		HumifortisURL:             strings.TrimRight(env("HUMIFORTIS_URL", "http://localhost:8080/api/v1"), "/"),
		HumifortisAPIKey:          os.Getenv("HUMIFORTIS_API_KEY"),
		FailPolicy:                FailPolicy(env("HUMIFORTIS_FAIL_POLICY", string(FailClosed))),
		RedisURL:                  os.Getenv("REDIS_URL"),
		TrustedHeaderSecret:       os.Getenv("GATEWAY_TRUSTED_HEADER_SECRET"),
		CAEPIssuer:                os.Getenv("CAEP_ISSUER"),
		CAEPAudience:              env("CAEP_AUDIENCE", "humifortis-enforcement-gateway"),
		CAEPPublicKeyPEM:          os.Getenv("CAEP_PUBLIC_KEY_PEM"),
		CAEPTenantID:              os.Getenv("CAEP_TENANT_ID"),
		CAEPJWKSURL:               os.Getenv("CAEP_JWKS_URL"),
		TrustedProxyCIDRs:         split(env("GATEWAY_TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128")),
		AAuthEnabled:              os.Getenv("AAUTH_ENABLED") == "true",
		AAuthTenantID:             os.Getenv("AAUTH_TENANT_ID"),
		AAuthFailPolicy:           FailPolicy(env("AAUTH_FAIL_POLICY", string(FailClosed))),
		AAuthAllowPrivateNetworks: os.Getenv("AAUTH_ALLOW_PRIVATE_NETWORKS") == "true",
		AAuthRootCAsFile:          os.Getenv("AAUTH_ROOT_CAS_FILE"),
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
	if c.AAuthWindow, err = duration("AAUTH_SIGNATURE_WINDOW", time.Minute); err != nil {
		return Config{}, err
	}
	if c.AAuthWindow > 5*time.Minute {
		return Config{}, fmt.Errorf("AAUTH_SIGNATURE_WINDOW cannot exceed 5m")
	}
	if c.AAuthProvidersRefresh, err = duration("AAUTH_PROVIDERS_REFRESH", 30*time.Second); err != nil {
		return Config{}, err
	}
	if c.AAuthProvidersMaxStale, err = duration("AAUTH_PROVIDERS_MAX_STALE", 5*time.Minute); err != nil {
		return Config{}, err
	}
	if c.AAuthFailPolicy != FailOpen && c.AAuthFailPolicy != FailClosed {
		return Config{}, fmt.Errorf("AAUTH_FAIL_POLICY must be fail_open or fail_closed")
	}
	if c.AAuthEnabled {
		if c.AAuthTenantID == "" {
			return Config{}, fmt.Errorf("AAUTH_ENABLED needs AAUTH_TENANT_ID: the tenant of an agent request is configuration, never a header")
		}
		if c.HumifortisAPIKey == "" {
			return Config{}, fmt.Errorf("AAUTH_ENABLED needs HUMIFORTIS_API_KEY (the key needs the scope aauth:verify)")
		}
		if c.RedisURL == "" {
			return Config{}, fmt.Errorf("AAUTH_ENABLED needs REDIS_URL: replay protection must be shared and atomic")
		}
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
