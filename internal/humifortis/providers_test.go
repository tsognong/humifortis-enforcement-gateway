package humifortis

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestProvidersTrustOnlyWhatIsDeclaredAndDropAStaleList(t *testing.T) {
	var down atomic.Bool
	var gotKey atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey.Store(r.Header.Get("X-API-Key"))
		if down.Load() || r.URL.Path != "/api/v1/agent-providers/trust" {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(`{"providers":{"Agents.Example.com":{"trust":"enterprise","pinned_jkt":["abc"],"max_token_lifetime_seconds":3600,"fresh_token_seconds":120}}}`))
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	p := NewProviders(srv.URL+"/api/v1", "k-1", time.Second, 5*time.Minute)
	p.now = func() time.Time { return now }

	if _, ok := p.Provider("agents.example.com"); ok {
		t.Fatal("nothing is trusted before the first answer")
	}
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotKey.Load() != "k-1" {
		t.Fatal("the gateway authenticates with its key")
	}
	pol, ok := p.Provider("AGENTS.example.com")
	if !ok || pol.Trust != "enterprise" || pol.MaxTokenLifetime != time.Hour || pol.FreshToken != 2*time.Minute || len(pol.PinnedJKT) != 1 {
		t.Fatalf("declared provider: %+v %v", pol, ok)
	}
	if _, ok := p.Provider("other.example.com"); ok {
		t.Fatal("an issuer that is not declared is not trusted")
	}

	down.Store(true)
	if err := p.Refresh(context.Background()); err == nil {
		t.Fatal("an unavailable Humifortis is an error")
	}
	now = now.Add(4 * time.Minute)
	if _, ok := p.Provider("agents.example.com"); !ok {
		t.Fatal("the last answer is used for a while")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := p.Provider("agents.example.com"); ok {
		t.Fatal("after the staleness bound nothing stays trusted")
	}
}
