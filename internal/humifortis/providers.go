package humifortis

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tsognong/humifortis-enforcement-gateway/internal/aauth"
)

// Providers keeps the agent providers the tenant declared in Humifortis (GET /agent-providers/trust) and answers the verifier
// whether an issuer is trusted. It is the verifier's TrustSource. An issuer that is not in the list is not trusted; when
// Humifortis cannot be reached for longer than maxStale the list is dropped, so that nothing stays trusted on a stale answer.
type Providers struct {
	base, key string
	http      *http.Client
	maxStale  time.Duration
	now       func() time.Time

	mu      sync.RWMutex
	list    map[string]aauth.ProviderPolicy
	fetched time.Time
}

func NewProviders(base, key string, timeout, maxStale time.Duration) *Providers {
	return &Providers{base: strings.TrimRight(base, "/"), key: key, http: &http.Client{Timeout: timeout}, maxStale: maxStale, now: time.Now}
}

type providerWire struct {
	Providers map[string]struct {
		Trust                   string   `json:"trust"`
		PinnedJKT               []string `json:"pinned_jkt"`
		MaxTokenLifetimeSeconds int      `json:"max_token_lifetime_seconds"`
		FreshTokenSeconds       int      `json:"fresh_token_seconds"`
	} `json:"providers"`
}

// Refresh reads the list once.
func (p *Providers) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base+"/agent-providers/trust", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", p.key)
	resp, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("humifortis returned status %d for the agent providers", resp.StatusCode)
	}
	var wire providerWire
	if err := json.NewDecoder(limited(resp.Body)).Decode(&wire); err != nil {
		return err
	}
	list := make(map[string]aauth.ProviderPolicy, len(wire.Providers))
	for host, w := range wire.Providers {
		list[strings.ToLower(host)] = aauth.ProviderPolicy{
			Trust: w.Trust, PinnedJKT: w.PinnedJKT,
			MaxTokenLifetime: time.Duration(w.MaxTokenLifetimeSeconds) * time.Second, FreshToken: time.Duration(w.FreshTokenSeconds) * time.Second,
		}
	}
	p.mu.Lock()
	p.list, p.fetched = list, p.now()
	p.mu.Unlock()
	return nil
}

// Run refreshes the list every interval until ctx ends. A failure keeps the last answer until it is too old.
func (p *Providers) Run(ctx context.Context, interval time.Duration, onError func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c, cancel := context.WithTimeout(ctx, 5*time.Second)
			if err := p.Refresh(c); err != nil && onError != nil {
				onError(err)
			}
			cancel()
		}
	}
}

// Provider implements aauth.TrustSource.
func (p *Providers) Provider(host string) (aauth.ProviderPolicy, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.fetched.IsZero() || p.now().Sub(p.fetched) > p.maxStale {
		return aauth.ProviderPolicy{}, false
	}
	pol, ok := p.list[strings.ToLower(host)]
	return pol, ok
}

// Declared reports whether the host is a provider the tenant declared (for the report of a refused proof).
func (p *Providers) Declared(host string) bool {
	_, ok := p.Provider(host)
	return ok
}

// limited bounds what Humifortis can make the gateway read.
func limited(r io.Reader) io.Reader { return io.LimitReader(r, 1<<20) }
