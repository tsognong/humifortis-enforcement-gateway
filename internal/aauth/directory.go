package aauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// KeyDirectory finds the public key a provider published under a kid. forceRefresh asks for a fresh fetch (an unknown kid, or a
// cached key that failed): the directory still honours its own floor on how often it fetches (draft 12.9).
type KeyDirectory interface {
	Key(ctx context.Context, issuerHost, kid string, forceRefresh bool) (JWK, *Error)
}

// DirectoryOptions configure the HTTP directory. The defaults are the safe ones; the two permissive options exist for a lab
// (a provider on a private network, a private CA) and are never to be set in production.
type DirectoryOptions struct {
	Timeout              time.Duration  // per fetch (default 2s)
	MaxBody              int64          // per document (default 64 KiB)
	MinRefresh           time.Duration  // at most one fetch per issuer in this interval (default 1 minute)
	MaxAge               time.Duration  // a cached document is discarded after this (default 24 hours)
	DefaultTTL           time.Duration  // when the response says nothing (default 10 minutes)
	NegativeTTL          time.Duration  // an unknown kid is remembered this long (default 1 minute)
	MaxIssuers           int            // bound of the cache (default 1000)
	AllowPrivateNetworks bool           // never in production
	RootCAs              *x509.CertPool // a private CA, for a lab
	// Dial replaces the dialler (a lab or a test that must reach a server whatever its name resolves to). Never in production.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	Now  func() time.Time
}

func (o DirectoryOptions) withDefaults() DirectoryOptions {
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
	if o.MaxBody <= 0 {
		o.MaxBody = 64 << 10
	}
	if o.MinRefresh <= 0 {
		o.MinRefresh = time.Minute
	}
	if o.MaxAge <= 0 {
		o.MaxAge = 24 * time.Hour
	}
	if o.DefaultTTL <= 0 {
		o.DefaultTTL = 10 * time.Minute
	}
	if o.NegativeTTL <= 0 {
		o.NegativeTTL = time.Minute
	}
	if o.MaxIssuers <= 0 {
		o.MaxIssuers = 1000
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// HTTPDirectory is the production KeyDirectory: it fetches {issuer}/.well-known/aauth-agent.json, then the provider's JWKS, under
// the egress rules of the draft (12.9) and of the threat model (SSRF, amplification): the issuer is allow-listed BEFORE any fetch
// (the caller's job), the address is checked at connect time, there are no redirects, a short timeout and a body cap, and the
// fetches per issuer are rate limited and cached.
type HTTPDirectory struct {
	opt    DirectoryOptions
	client *http.Client

	mu      sync.Mutex
	issuers map[string]*issuerEntry
}

type issuerEntry struct {
	keys        map[string]JWK
	fetchedAt   time.Time
	expiresAt   time.Time
	lastAttempt time.Time
	lastErr     *Error
	unknown     map[string]time.Time // kid -> until when it is remembered as unknown
}

// NewHTTPDirectory builds the directory.
func NewHTTPDirectory(opt DirectoryOptions) *HTTPDirectory {
	opt = opt.withDefaults()
	d := &HTTPDirectory{opt: opt, issuers: map[string]*issuerEntry{}}
	dialer := &net.Dialer{Timeout: opt.Timeout}
	if !opt.AllowPrivateNetworks {
		dialer.Control = func(_, address string, _ syscall.RawConn) error { return checkEgressAddress(address) }
	}
	dial := dialer.DialContext
	if opt.Dial != nil {
		dial = opt.Dial
	}
	transport := &http.Transport{
		Proxy:                 nil, // never through an environment proxy: the address check would not see the real destination
		DialContext:           dial,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: opt.RootCAs},
		TLSHandshakeTimeout:   opt.Timeout,
		ResponseHeaderTimeout: opt.Timeout,
		MaxIdleConns:          16,
		IdleConnTimeout:       30 * time.Second,
		DisableCompression:    true,
	}
	d.client = &http.Client{
		Transport:     transport,
		Timeout:       opt.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, // a redirect is a failure
	}
	return d
}

// Key implements KeyDirectory.
func (d *HTTPDirectory) Key(ctx context.Context, issuerHost, kid string, forceRefresh bool) (JWK, *Error) {
	host, err := validHost(issuerHost)
	if err != nil {
		return JWK{}, failDetail(IssuerMismatch, "the issuer is not a host name")
	}
	now := d.opt.Now()

	d.mu.Lock()
	e := d.issuers[host]
	if e != nil {
		if until, bad := e.unknown[kid]; bad && now.Before(until) {
			d.mu.Unlock()
			return JWK{}, failDetail(UnknownKey, "the key id is not published by the issuer (remembered)")
		}
		fresh := now.Before(e.expiresAt) && now.Sub(e.fetchedAt) < d.opt.MaxAge
		if k, have := e.keys[kid]; have && fresh && !forceRefresh {
			d.mu.Unlock()
			return k, nil
		}
		// a refresh is wanted (stale, unknown kid, or a cached key that failed): at most one fetch a minute per issuer
		if now.Sub(e.lastAttempt) < d.opt.MinRefresh {
			k, have := e.keys[kid]
			stillOK := now.Sub(e.fetchedAt) < d.opt.MaxAge
			lastErr := e.lastErr
			d.mu.Unlock()
			if have && stillOK && !forceRefresh {
				return k, nil // use the cache while the floor holds (a stale cache is better than a flood of fetches)
			}
			if lastErr != nil && !have {
				return JWK{}, lastErr
			}
			if have && stillOK {
				return k, nil
			}
			return JWK{}, failDetail(UnknownKey, "the key is not known and the issuer was fetched a moment ago")
		}
	} else {
		if len(d.issuers) >= d.opt.MaxIssuers {
			d.evictOldestLocked()
		}
		e = &issuerEntry{keys: map[string]JWK{}, unknown: map[string]time.Time{}}
		d.issuers[host] = e
	}
	e.lastAttempt = now
	d.mu.Unlock()

	keys, ttl, ferr := d.fetch(ctx, host)

	d.mu.Lock()
	defer d.mu.Unlock()
	if ferr != nil {
		e.lastErr = ferr
		// a failure keeps the cache (draft 12.9): the keys it has are used until they are 24 hours old
		if k, have := e.keys[kid]; have && now.Sub(e.fetchedAt) < d.opt.MaxAge {
			return k, nil
		}
		return JWK{}, ferr
	}
	e.keys, e.fetchedAt, e.expiresAt, e.lastErr = keys, now, now.Add(ttl), nil
	if k, have := keys[kid]; have {
		delete(e.unknown, kid)
		return k, nil
	}
	if len(e.unknown) < 64 {
		e.unknown[kid] = now.Add(d.opt.NegativeTTL)
	}
	return JWK{}, failDetail(UnknownKey, "the key id is not published by the issuer")
}

func (d *HTTPDirectory) evictOldestLocked() {
	var oldest string
	var at time.Time
	for h, e := range d.issuers {
		if oldest == "" || e.lastAttempt.Before(at) {
			oldest, at = h, e.lastAttempt
		}
	}
	delete(d.issuers, oldest)
}

type providerMetadata struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

func (d *HTTPDirectory) fetch(ctx context.Context, host string) (map[string]JWK, time.Duration, *Error) {
	metaURL := "https://" + host + "/.well-known/" + DWKAgent
	raw, _, err := d.get(ctx, metaURL)
	if err != nil {
		return nil, 0, failDetail(IssuerMissing, "the issuer metadata could not be fetched")
	}
	var meta providerMetadata
	if json.Unmarshal(raw, &meta) != nil {
		return nil, 0, failDetail(IssuerMissing, "the issuer metadata is not JSON")
	}
	if meta.Issuer != "https://"+host {
		// byte for byte: a document served for another host (or one that only looks alike) is not this issuer's
		return nil, 0, failDetail(IssuerMismatch, "the metadata issuer is not the host it was fetched from")
	}
	jwksHost, ok := jwksHostOf(meta.JWKSURI)
	if !ok || jwksHost != host {
		return nil, 0, failDetail(IssuerMismatch, "the key set is not on the issuer's host")
	}
	rawKeys, ttl, err := d.get(ctx, meta.JWKSURI)
	if err != nil {
		return nil, 0, failDetail(IssuerMissing, "the issuer key set could not be fetched")
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if json.Unmarshal(rawKeys, &set) != nil {
		return nil, 0, failDetail(IssuerMissing, "the key set is not JSON")
	}
	keys := map[string]JWK{}
	for _, rk := range set.Keys {
		k, kerr := UnmarshalJWK(rk)
		if kerr != nil || k.Kid == "" {
			continue // a member the profile cannot use does not spoil the others (draft 12.9)
		}
		if _, kerr := k.key(); kerr != nil {
			continue
		}
		keys[k.Kid] = k
	}
	if len(keys) == 0 {
		return nil, 0, failDetail(UnknownKey, "the issuer publishes no usable key")
	}
	if ttl <= 0 || ttl > d.opt.MaxAge {
		ttl = d.opt.DefaultTTL
	}
	if ttl < d.opt.MinRefresh {
		ttl = d.opt.MinRefresh
	}
	return keys, ttl, nil
}

func jwksHostOf(rawURL string) (string, bool) {
	rest, ok := strings.CutPrefix(rawURL, "https://")
	if !ok {
		return "", false
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		return "", false // a key set has a path
	}
	h, err := validHost(rest[:end])
	return h, err == nil
}

// get fetches an https document under the egress rules and returns its body and the freshness the server declared.
func (d *HTTPDirectory) get(ctx context.Context, rawURL string) ([]byte, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, d.opt.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, d.opt.MaxBody+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(body)) > d.opt.MaxBody {
		return nil, 0, fmt.Errorf("document too large")
	}
	return body, freshness(resp.Header, d.opt.Now()), nil
}

// freshness is the lifetime a response declares (Cache-Control max-age, else Expires); 0 when it says nothing or says no-store.
func freshness(h http.Header, now time.Time) time.Duration {
	cc := strings.ToLower(h.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "no-cache") {
		return 0
	}
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "max-age="); ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				return time.Duration(n) * time.Second
			}
		}
	}
	if exp := h.Get("Expires"); exp != "" {
		if t, err := http.ParseTime(exp); err == nil && t.After(now) {
			return t.Sub(now)
		}
	}
	return 0
}

// checkEgressAddress refuses to connect to an address the verifier must never reach: loopback, private, link-local (which holds
// the cloud metadata address), carrier-grade NAT, multicast, unspecified, and the IPv6 unique-local range. It runs at connect
// time on the address actually dialled, so a name that resolves to a private address (or is rebound to one) is refused too.
func checkEgressAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("egress refused: bad address")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return errors.New("egress refused: not an address")
	}
	ip = ip.Unmap()
	switch {
	case ip.IsLoopback(), ip.IsPrivate(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsMulticast(), ip.IsUnspecified(), ip.IsInterfaceLocalMulticast():
		return errors.New("egress refused: not a public address")
	}
	if cgnat := netip.MustParsePrefix("100.64.0.0/10"); cgnat.Contains(ip) {
		return errors.New("egress refused: carrier-grade NAT range")
	}
	if ip.Is4() && ip.As4()[0] == 0 {
		return errors.New("egress refused: this-network range")
	}
	return nil
}
