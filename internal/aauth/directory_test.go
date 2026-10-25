package aauth

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// provider is a fake agent provider served over TLS; the directory reaches it whatever the name resolves to.
type provider struct {
	srv      *httptest.Server
	keys     atomic.Value // []JWK
	metaHits atomic.Int64
	keyHits  atomic.Int64
	issuer   string // what the metadata claims (default https://example.com)
	jwksURI  string
	cache    string
	status   atomic.Int64
	redirect atomic.Bool
	big      atomic.Bool
}

func newProvider(t *testing.T, keys ...JWK) *provider {
	t.Helper()
	p := &provider{issuer: "https://example.com", jwksURI: "https://example.com/jwks"}
	p.keys.Store(keys)
	p.status.Store(200)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/aauth-agent.json", func(w http.ResponseWriter, r *http.Request) {
		p.metaHits.Add(1)
		if p.redirect.Load() {
			http.Redirect(w, r, "https://other.example.net/x", http.StatusFound)
			return
		}
		if s := int(p.status.Load()); s != 200 {
			w.WriteHeader(s)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": p.issuer, "jwks_uri": p.jwksURI})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		p.keyHits.Add(1)
		if p.cache != "" {
			w.Header().Set("Cache-Control", p.cache)
		}
		if p.big.Load() {
			_, _ = w.Write([]byte(`{"keys":[],"pad":"` + strings.Repeat("a", 70<<10) + `"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": p.keys.Load().([]JWK)})
	})
	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func (p *provider) directory(c *clock, mod func(*DirectoryOptions)) *HTTPDirectory {
	addr := p.srv.Listener.Addr().String()
	opt := DirectoryOptions{
		RootCAs: p.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		Now: c.now,
	}
	if mod != nil {
		mod(&opt)
	}
	return NewHTTPDirectory(opt)
}

func TestDirectory_FetchesAndCaches(t *testing.T) {
	k := NewKey("k1")
	p := newProvider(t, k.JWK)
	c := &clock{t: t0}
	d := p.directory(c, nil)

	got, err := d.Key(context.Background(), "example.com", "k1", false)
	noFail(t, err)
	eq(t, k.JWK.X, got.X)
	_, err = d.Key(context.Background(), "example.com", "k1", false)
	noFail(t, err)
	eq(t, int64(1), p.metaHits.Load(), "the second lookup is served from the cache")
	eq(t, int64(1), p.keyHits.Load())
}

func TestDirectory_AnUnknownKidIsRememberedAndFetchesAreRateLimited(t *testing.T) {
	p := newProvider(t, NewKey("k1").JWK)
	c := &clock{t: t0}
	d := p.directory(c, nil)
	_, err := d.Key(context.Background(), "example.com", "k1", false)
	noFail(t, err)

	for i := 0; i < 20; i++ {
		_, err = d.Key(context.Background(), "example.com", "nope", false)
		refused(t, err, UnknownKey)
	}
	isTrue(t, p.keyHits.Load() <= 2, "twenty lookups of an unknown kid did not become twenty fetches")

	// forcing a refresh is still bounded: one fetch a minute per issuer
	for i := 0; i < 10; i++ {
		_, _ = d.Key(context.Background(), "example.com", "k1", true)
	}
	isTrue(t, p.keyHits.Load() <= 3, "forced refreshes are floored too")

	c.add(2 * time.Minute)
	_, err = d.Key(context.Background(), "example.com", "k1", true)
	noFail(t, err)
	isTrue(t, p.keyHits.Load() >= 2, "after the floor a refresh fetches")
}

func TestDirectory_APublishedKeyAppearsAfterARefresh(t *testing.T) {
	k1 := NewKey("k1")
	p := newProvider(t, k1.JWK)
	c := &clock{t: t0}
	d := p.directory(c, nil)
	_, err := d.Key(context.Background(), "example.com", "k1", false)
	noFail(t, err)

	k2 := NewKey("k2")
	p.keys.Store([]JWK{k1.JWK, k2.JWK})
	c.add(2 * time.Minute)
	got, err := d.Key(context.Background(), "example.com", "k2", false)
	noFail(t, err, "an unknown kid triggers a refresh once the floor has passed")
	eq(t, k2.JWK.X, got.X)
}

func TestDirectory_AStaleCacheSurvivesAFailureForAtMostTwentyFourHours(t *testing.T) {
	k := NewKey("k1")
	p := newProvider(t, k.JWK)
	p.cache = "max-age=60"
	c := &clock{t: t0}
	d := p.directory(c, nil)
	_, err := d.Key(context.Background(), "example.com", "k1", false)
	noFail(t, err)

	p.status.Store(500)
	c.add(5 * time.Minute)
	_, err = d.Key(context.Background(), "example.com", "k1", false)
	noFail(t, err, "the provider is down: the cached key is used")

	c.add(25 * time.Hour)
	_, err = d.Key(context.Background(), "example.com", "k1", false)
	isTrue(t, err != nil, "after 24 hours the cache is no longer trusted")
}

func TestDirectory_TheMetadataIssuerMustBeTheHostItWasFetchedFrom(t *testing.T) {
	p := newProvider(t, NewKey("k1").JWK)
	p.issuer = "https://evil.example.net"
	d := p.directory(&clock{t: t0}, nil)
	_, err := d.Key(context.Background(), "example.com", "k1", false)
	refused(t, err, IssuerMismatch)

	p2 := newProvider(t, NewKey("k1").JWK)
	p2.issuer = "https://example.com/"
	_, err = p2.directory(&clock{t: t0}, nil).Key(context.Background(), "example.com", "k1", false)
	refused(t, err, IssuerMismatch)
}

func TestDirectory_TheKeySetMustBeOnTheIssuersHost(t *testing.T) {
	for _, uri := range []string{"https://other.example.net/jwks", "http://example.com/jwks", "https://example.com", "https://example.com:8443/jwks"} {
		p := newProvider(t, NewKey("k1").JWK)
		p.jwksURI = uri
		_, err := p.directory(&clock{t: t0}, nil).Key(context.Background(), "example.com", "k1", false)
		if err == nil || err.Code != IssuerMismatch {
			t.Fatalf("%s: expected issuer_mismatch, got %v", uri, err)
		}
	}
}

func TestDirectory_ARedirectIsAFailure(t *testing.T) {
	p := newProvider(t, NewKey("k1").JWK)
	p.redirect.Store(true)
	_, err := p.directory(&clock{t: t0}, nil).Key(context.Background(), "example.com", "k1", false)
	refused(t, err, IssuerMissing)
}

func TestDirectory_ADocumentOverTheCapIsRefused(t *testing.T) {
	p := newProvider(t, NewKey("k1").JWK)
	p.big.Store(true)
	_, err := p.directory(&clock{t: t0}, nil).Key(context.Background(), "example.com", "k1", false)
	refused(t, err, IssuerMissing)
}

func TestDirectory_KeysThatCarryAPrivateMemberOrNoAlgAreIgnored(t *testing.T) {
	good := NewKey("good")
	noAlg := NewKey("noalg").JWK
	noAlg.Alg = ""
	p := newProvider(t, noAlg, good.JWK)
	d := p.directory(&clock{t: t0}, nil)
	_, err := d.Key(context.Background(), "example.com", "good", false)
	noFail(t, err, "a member the profile cannot use does not spoil the others")
	_, err = d.Key(context.Background(), "example.com", "noalg", false)
	refused(t, err, UnknownKey)
}

func TestDirectory_RefusesAnIssuerThatIsNotAHostName(t *testing.T) {
	d := NewHTTPDirectory(DirectoryOptions{})
	for _, h := range []string{"10.0.0.1", "localhost", "a.example.com:8443", "https://a.example.com", ""} {
		_, err := d.Key(context.Background(), h, "k", false)
		refused(t, err, IssuerMismatch)
	}
}

func TestDirectory_NeverConnectsToAnAddressItMustNotReach(t *testing.T) {
	// the default dialler refuses private addresses at connect time: the lookup of a name that resolves there fails
	d := NewHTTPDirectory(DirectoryOptions{Timeout: 500 * time.Millisecond})
	srv := httptest.NewTLSServer(http.NewServeMux()) // on 127.0.0.1
	defer srv.Close()
	d.client.Transport.(*http.Transport).DialContext = (&net.Dialer{
		Control: func(_, address string, _ syscall.RawConn) error { return checkEgressAddress(address) },
	}).DialContext
	_, err := d.Key(context.Background(), "example.com", "k", false)
	isTrue(t, err != nil, "no key came from a private address")
}

func TestCheckEgressAddress(t *testing.T) {
	blocked := []string{
		"127.0.0.1:443", "10.1.2.3:443", "172.16.0.9:443", "192.168.1.1:443", "169.254.169.254:80", "100.64.0.1:443", "0.0.0.0:443",
		"[::1]:443", "[fe80::1]:443", "[fc00::1]:443", "[::ffff:127.0.0.1]:443", "[::ffff:10.0.0.1]:443", "224.0.0.1:443", "[ff02::1]:443",
	}
	for _, a := range blocked {
		isTrue(t, checkEgressAddress(a) != nil, a+" must be refused")
	}
	for _, a := range []string{"93.184.216.34:443", "[2606:4700:4700::1111]:443", "8.8.8.8:443"} {
		noErr(t, checkEgressAddress(a), a+" is public")
	}
	isTrue(t, checkEgressAddress("not-an-address") != nil)
	isTrue(t, checkEgressAddress("example.com:443") != nil, "a name is never an address: the dialler gets resolved addresses")
}

func TestFreshness(t *testing.T) {
	now := t0
	h := http.Header{}
	eq(t, time.Duration(0), freshness(h, now))
	h.Set("Cache-Control", "public, max-age=300")
	eq(t, 300*time.Second, freshness(h, now))
	h.Set("Cache-Control", "no-store")
	eq(t, time.Duration(0), freshness(h, now))
	h = http.Header{}
	h.Set("Expires", now.Add(time.Hour).Format(http.TimeFormat))
	isTrue(t, freshness(h, now) >= 59*time.Minute, "Expires")
}
