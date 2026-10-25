package aauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── a world: one provider, one agent, one trusted tenant ───────────────────────────────────────────────────────────

const (
	testHost    = "agents.example.com"
	testIssuer  = "https://agents.example.com"
	testSub     = "aauth:planner@agents.example.com"
	testAuthHdr = "agents.example.com"
)

var t0 = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

type fakeDirectory struct {
	mu        sync.Mutex
	keys      map[string]JWK // host|kid
	fetches   int
	failWith  *Error
	refreshed map[string]JWK // appears only after a forced refresh (a silent re-keying)
}

func (d *fakeDirectory) Key(_ context.Context, host, kid string, force bool) (JWK, *Error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fetches++
	if d.failWith != nil {
		return JWK{}, d.failWith
	}
	if force && d.refreshed != nil {
		for k, v := range d.refreshed {
			d.keys[k] = v
		}
	}
	k, ok := d.keys[host+"|"+kid]
	if !ok {
		return JWK{}, failDetail(UnknownKey, "unknown")
	}
	return k, nil
}

type fakeTrust map[string]ProviderPolicy

func (f fakeTrust) Provider(host string) (ProviderPolicy, bool) { p, ok := f[host]; return p, ok }

type fakeReplay struct {
	mu   sync.Mutex
	seen map[string]bool
	err  error
}

func (r *fakeReplay) FirstUse(_ context.Context, key string, _ time.Duration) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return false, r.err
	}
	if r.seen == nil {
		r.seen = map[string]bool{}
	}
	if r.seen[key] {
		return false, nil
	}
	r.seen[key] = true
	return true, nil
}

type fakeRevocations map[string]bool

func (f fakeRevocations) Revoked(_ context.Context, iss, jti string) (bool, error) {
	return f[iss+"|"+jti], nil
}

type world struct {
	provider Key
	agent    Key
	dir      *fakeDirectory
	trust    fakeTrust
	replay   *fakeReplay
	revoked  fakeRevocations
	verifier *Verifier
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{provider: NewKey("provider-1"), agent: NewKey(""), trust: fakeTrust{testHost: {Trust: "enterprise"}}, replay: &fakeReplay{}, revoked: fakeRevocations{}}
	w.dir = &fakeDirectory{keys: map[string]JWK{testHost + "|provider-1": w.provider.JWK}}
	v, err := NewVerifier(Config{TenantID: "tenant-a"}, w.trust, w.dir, w.replay, w.revoked)
	noErr(t, err)
	w.verifier = v.WithClock(func() time.Time { return t0 })
	return w
}

// token issues the agent's token with sane defaults, adjustable by the test.
func (w *world) token(mod func(*TokenSpec)) string {
	s := TokenSpec{Issuer: testIssuer, Subject: testSub, ID: "jti-1", Agent: w.agent.JWK, IssuedAt: t0.Add(-time.Minute), ExpiresAt: t0.Add(time.Hour)}
	if mod != nil {
		mod(&s)
	}
	return w.provider.IssueAgentToken(s)
}

// request signs GET /v1/things for the agent.
func (w *world) request(token string, mod func(*Request, *SignOptions)) Request {
	req := Request{Method: "GET", Authority: testAuthHdr, Path: "/v1/things", Scheme: "https", Header: http.Header{}, SourceIP: "203.0.113.9"}
	opt := SignOptions{Created: t0.Add(-2 * time.Second)}
	if mod != nil {
		mod(&req, &opt)
	}
	SignRequest(req.Header, req.Method, req.Authority, req.Path, req.Query, req.Scheme, w.agent, token, opt)
	return req
}

func (w *world) verify(req Request) (*Verified, *Error) {
	return w.verifier.Verify(context.Background(), req)
}

// ── the happy path ─────────────────────────────────────────────────────────────────────────────────────────────

func TestVerify_AValidAgentIsVerified(t *testing.T) {
	w := newWorld(t)
	v, err := w.verify(w.request(w.token(nil), nil))
	noFail(t, err)
	eq(t, "agent:aauth:planner@agents.example.com", v.AgentID)
	eq(t, testSub, v.Sub)
	eq(t, testHost, v.Issuer)
	eq(t, "enterprise", v.Trust)
	eq(t, w.agent.Thumbprint(), v.JKT)
	eq(t, AlgEd25519, v.KeyAlg)
	eq(t, "jti-1", v.TokenID)
	isTrue(t, v.TokenFresh, "issued a minute ago: fresh within the default 5 minutes")
	eq(t, []string{"@method", "@authority", "@path", "signature-key"}, v.Covered)
}

func TestVerify_FreshnessFollowsTheProvidersPolicy(t *testing.T) {
	w := newWorld(t)
	w.trust[testHost] = ProviderPolicy{Trust: "partner", FreshToken: 30 * time.Second}
	v, err := w.verify(w.request(w.token(nil), nil))
	noFail(t, err)
	isFalse(t, v.TokenFresh, "a minute old is not fresh for a 30-second policy")
}

// ── protocol refusals, one by one ──────────────────────────────────────────────────────────────────────────────

func TestVerify_TheThreeFieldsAreRequired(t *testing.T) {
	w := newWorld(t)
	for _, drop := range []string{"Signature", "Signature-Input", "Signature-Key"} {
		req := w.request(w.token(nil), nil)
		req.Header.Del(drop)
		_, err := w.verify(req)
		refused(t, err, InvalidRequest)
	}
}

func TestVerify_TheSignatureMustCoverWhatTheProfileRequires(t *testing.T) {
	w := newWorld(t)
	for _, covered := range [][]string{
		{"@method", "@authority", "signature-key"}, // no path
		{"@method", "@path", "signature-key"},      // no authority
		{"@authority", "@path", "signature-key"},   // no method
		{"@method", "@authority", "@path"},         // a different token could be swapped in
	} {
		req := w.request(w.token(nil), func(_ *Request, o *SignOptions) { o.Covered = covered })
		_, err := w.verify(req)
		refused(t, err, InvalidInput, ReasonUncovered)
		isTrue(t, len(err.Required) == 4, "the refusal lists what is required")
		isTrue(t, strings.Contains(err.SignatureError(), "required_input"), err.SignatureError())
	}
}

func TestVerify_AnAAuthCredentialMustBeCovered(t *testing.T) {
	w := newWorld(t)
	req := w.request(w.token(nil), func(r *Request, _ *SignOptions) { r.Header.Set("Authorization", "AAuth abc123") })
	_, err := w.verify(req)
	refused(t, err, InvalidInput, ReasonUncovered)

	covered := w.request(w.token(nil), func(r *Request, o *SignOptions) {
		r.Header.Set("Authorization", "AAuth abc123")
		o.Covered = []string{"@method", "@authority", "@path", "signature-key", "authorization"}
	})
	_, err = w.verify(covered)
	noFail(t, err)
}

func TestVerify_TheCreatedWindow(t *testing.T) {
	cases := map[string]time.Duration{"old": -61 * time.Second, "future": 10 * time.Second}
	for name, offset := range cases {
		w := newWorld(t)
		req := w.request(w.token(nil), func(_ *Request, o *SignOptions) { o.Created = t0.Add(offset) })
		_, err := w.verify(req)
		refused(t, err, InvalidSignature, ReasonClockSkew)
		_ = name
	}
	w := newWorld(t)
	_, err := w.verify(w.request(w.token(nil), func(_ *Request, o *SignOptions) { o.Created = t0.Add(-59 * time.Second) }))
	noFail(t, err, "inside the window")
}

func TestVerify_OnlyTheJwtSchemeIsAccepted(t *testing.T) {
	w := newWorld(t)
	for _, scheme := range []string{`sig=hwk;kty="OKP"`, `sig=jwks_uri;jwks_uri="https://x.example/jwks"`, `sig=x509`} {
		req := w.request(w.token(nil), nil)
		req.Header.Set("Signature-Key", scheme)
		_, err := w.verify(req)
		refused(t, err, UnsupportedScheme)
	}
}

func TestVerify_TheAlgParameterMustNotBeSent(t *testing.T) {
	w := newWorld(t)
	req := w.request(w.token(nil), nil)
	in := req.Header.Get("Signature-Input")
	req.Header.Set("Signature-Input", in+`;alg="ed25519"`)
	_, err := w.verify(req)
	refused(t, err, InvalidRequest)
}

func TestVerify_ATamperedRequestFails(t *testing.T) {
	w := newWorld(t)
	req := w.request(w.token(nil), nil)
	req.Path = "/v1/other"
	_, err := w.verify(req)
	refused(t, err, InvalidSignature, ReasonKeyBinding)

	req = w.request(w.token(nil), nil)
	req.Method = "DELETE"
	_, err = w.verify(req)
	refused(t, err, InvalidSignature)

	req = w.request(w.token(nil), nil)
	req.Authority = "evil.example.com"
	_, err = w.verify(req)
	refused(t, err, InvalidSignature)
}

func TestVerify_ASwappedTokenFails(t *testing.T) {
	w := newWorld(t)
	req := w.request(w.token(nil), nil)
	// another valid token of the same agent, put in the field after the signature was made: the field is covered
	other := w.token(func(s *TokenSpec) { s.ID = "jti-2" })
	req.Header.Set("Signature-Key", `sig=jwt;jwt="`+other+`"`)
	_, err := w.verify(req)
	refused(t, err, InvalidSignature)
}

// ── the agent token ────────────────────────────────────────────────────────────────────────────────────────────

func TestVerify_TokenAlgorithmsOtherThanTheProfilesAreRefused(t *testing.T) {
	w := newWorld(t)
	for _, alg := range []string{"none", "EdDSA", "HS256", "RS256", "ES512"} {
		tok := w.token(func(s *TokenSpec) { s.Alg = alg })
		_, err := w.verify(w.request(tok, nil))
		refused(t, err, UnsupportedAlgorithm)
	}
}

func TestVerify_TokenShape(t *testing.T) {
	w := newWorld(t)
	cases := map[string]func(*TokenSpec){
		"wrong typ": func(s *TokenSpec) { s.Typ = "JWT" },
		"wrong dwk": func(s *TokenSpec) { s.Dwk = "aauth-person.json" },
		"no jti":    func(s *TokenSpec) { s.ID = "" },
	}
	for name, mod := range cases {
		_, err := w.verify(w.request(w.token(mod), nil))
		if err == nil || err.Code != InvalidJWT {
			t.Fatalf("%s: expected invalid_jwt, got %v", name, err)
		}
	}
}

func TestVerify_TokenTimes(t *testing.T) {
	w := newWorld(t)
	_, err := w.verify(w.request(w.token(func(s *TokenSpec) { s.ExpiresAt = t0.Add(-time.Second) }), nil))
	refused(t, err, ExpiredJWT)

	_, err = w.verify(w.request(w.token(func(s *TokenSpec) { s.IssuedAt = t0.Add(time.Minute) }), nil))
	refused(t, err, InvalidJWT, ReasonNotYetValid)

	_, err = w.verify(w.request(w.token(func(s *TokenSpec) { s.ExpiresAt = s.IssuedAt.Add(25 * time.Hour) }), nil))
	refused(t, err, InvalidJWT, ReasonLifetime)

	w.trust[testHost] = ProviderPolicy{Trust: "partner", MaxTokenLifetime: 10 * time.Minute}
	_, err = w.verify(w.request(w.token(func(s *TokenSpec) { s.ExpiresAt = s.IssuedAt.Add(30 * time.Minute) }), nil))
	refused(t, err, InvalidJWT, ReasonLifetime)
}

func TestVerify_TheIssuerMustBeTheDomainOfTheAgentIdentifier(t *testing.T) {
	w := newWorld(t)
	for name, mod := range map[string]func(*TokenSpec){
		"another domain":       func(s *TokenSpec) { s.Subject = "aauth:planner@other.example.org" },
		"a port in the issuer": func(s *TokenSpec) { s.Issuer = "https://agents.example.com:8443" },
		"a path in the issuer": func(s *TokenSpec) { s.Issuer = "https://agents.example.com/tenant1" },
		"a trailing slash":     func(s *TokenSpec) { s.Issuer = "https://agents.example.com/" },
		"http":                 func(s *TokenSpec) { s.Issuer = "http://agents.example.com" },
		"user information":     func(s *TokenSpec) { s.Issuer = "https://user@agents.example.com" },
	} {
		_, err := w.verify(w.request(w.token(mod), nil))
		if err == nil || err.Code != IssuerMismatch {
			t.Fatalf("%s: expected issuer_mismatch, got %v", name, err)
		}
	}
}

func TestVerify_TheAgentIdentifierGrammar(t *testing.T) {
	w := newWorld(t)
	for _, sub := range []string{"planner@agents.example.com", "aauth:@agents.example.com", "aauth:Planner@agents.example.com", "aauth:pla nner@agents.example.com", "aauth:planner@", "aauth:planner", "aauth:a@b@agents.example.com", "aauth:" + strings.Repeat("a", 65) + "@agents.example.com"} {
		_, err := w.verify(w.request(w.token(func(s *TokenSpec) { s.Subject = sub }), nil))
		if err == nil || (err.Code != InvalidJWT && err.Code != IssuerMismatch) {
			t.Fatalf("%q: expected a refusal, got %v", sub, err)
		}
		isTrue(t, err.Code != "", sub)
	}
}

// ── trust and keys ─────────────────────────────────────────────────────────────────────────────────────────────

func TestVerify_AnUndeclaredProviderIsRefusedBeforeAnyFetch(t *testing.T) {
	w := newWorld(t)
	delete(w.trust, testHost)
	_, err := w.verify(w.request(w.token(nil), nil))
	refused(t, err, UnknownIssuer)
	eq(t, 0, w.dir.fetches, "the verifier did not look the stranger up")
}

func TestVerify_ATokenSignedByAKeyTheProviderDoesNotPublishIsRefused(t *testing.T) {
	w := newWorld(t)
	forger := NewKey("provider-1") // the right kid, another key
	tok := forger.IssueAgentToken(TokenSpec{Issuer: testIssuer, Subject: testSub, ID: "j", Agent: w.agent.JWK, IssuedAt: t0.Add(-time.Minute), ExpiresAt: t0.Add(time.Hour)})
	_, err := w.verify(w.request(tok, nil))
	refused(t, err, InvalidJWT)

	unknownKid := NewKey("not-published").IssueAgentToken(TokenSpec{Issuer: testIssuer, Subject: testSub, ID: "j", Agent: w.agent.JWK, IssuedAt: t0.Add(-time.Minute), ExpiresAt: t0.Add(time.Hour)})
	_, err = w.verify(w.request(unknownKid, nil))
	refused(t, err, UnknownKey)
}

func TestVerify_ASilentReKeyingIsFollowedOnceAfterARefresh(t *testing.T) {
	w := newWorld(t)
	rotated := NewKey("provider-2")
	w.dir.refreshed = map[string]JWK{testHost + "|provider-2": rotated.JWK}
	tok := rotated.IssueAgentToken(TokenSpec{Issuer: testIssuer, Subject: testSub, ID: "j", Agent: w.agent.JWK, IssuedAt: t0.Add(-time.Minute), ExpiresAt: t0.Add(time.Hour)})
	_, err := w.verify(w.request(tok, nil))
	noFail(t, err, "the key appeared on the refresh")
}

func TestVerify_TheDirectoryFailingIsRefusedNotAllowed(t *testing.T) {
	w := newWorld(t)
	w.dir.failWith = failDetail(IssuerMissing, "down")
	_, err := w.verify(w.request(w.token(nil), nil))
	refused(t, err, IssuerMissing)
}

func TestVerify_PinnedKeys(t *testing.T) {
	w := newWorld(t)
	w.trust[testHost] = ProviderPolicy{Trust: "enterprise", PinnedJKT: []string{w.agent.Thumbprint()}}
	_, err := w.verify(w.request(w.token(nil), nil))
	noFail(t, err, "the pinned key is accepted")

	w.trust[testHost] = ProviderPolicy{Trust: "enterprise", PinnedJKT: []string{NewKey("").Thumbprint()}}
	_, err = w.verify(w.request(w.token(nil), func(r *Request, _ *SignOptions) { r.Query = "x=2" }))
	refused(t, err, UnknownKey, ReasonPinnedKey)
}

func TestVerify_TheBoundKeyMustBeUsableAndPublic(t *testing.T) {
	w := newWorld(t)
	bad := w.agent.JWK
	bad.Alg = ""
	_, err := w.verify(w.request(w.token(func(s *TokenSpec) { s.Agent = bad }), nil))
	refused(t, err, InvalidKey)

	mismatch := w.agent.JWK
	mismatch.Alg = AlgES256
	_, err = w.verify(w.request(w.token(func(s *TokenSpec) { s.Agent = mismatch }), nil))
	refused(t, err, InvalidKey)
}

// ── replay, revocation, dependencies ───────────────────────────────────────────────────────────────────────────

func TestVerify_ASignedRequestIsAcceptedOnce(t *testing.T) {
	w := newWorld(t)
	req := w.request(w.token(nil), nil)
	_, err := w.verify(req)
	noFail(t, err)
	_, err = w.verify(req)
	refused(t, err, InvalidSignature, ReasonReplay)

	// another request of the same agent is another signature
	_, err = w.verify(w.request(w.token(nil), func(r *Request, _ *SignOptions) { r.Path = "/v1/other" }))
	noFail(t, err)
}

func TestVerify_ReplayKeysAreOfTheTenant(t *testing.T) {
	a := newWorld(t)
	req := a.request(a.token(nil), nil)
	_, err := a.verify(req)
	noFail(t, err)

	// the same request presented to a verifier of another tenant sharing the store is another key
	other, verr := NewVerifier(Config{TenantID: "tenant-b"}, a.trust, a.dir, a.replay, a.revoked)
	noErr(t, verr)
	_, err = other.WithClock(func() time.Time { return t0 }).Verify(context.Background(), req)
	noFail(t, err, "the replay key is prefixed by the gateway's tenant")
}

func TestVerify_OnlyAVerifiedRequestIsRecorded(t *testing.T) {
	w := newWorld(t)
	for i := 0; i < 5; i++ {
		req := w.request(w.token(nil), func(_ *Request, o *SignOptions) { o.Created = t0.Add(-time.Hour) })
		_, err := w.verify(req)
		refused(t, err, InvalidSignature, ReasonClockSkew)
	}
	eq(t, 0, len(w.replay.seen), "a flood of refused requests fills nothing")
}

func TestVerify_ARevokedTokenIsRefused(t *testing.T) {
	w := newWorld(t)
	w.revoked[testIssuer+"|jti-1"] = true
	_, err := w.verify(w.request(w.token(nil), nil))
	refused(t, err, InvalidJWT, ReasonRevoked)
}

func TestVerify_AnUnavailableReplayStoreFailsClosed(t *testing.T) {
	w := newWorld(t)
	w.replay.err = errors.New("redis down")
	_, err := w.verify(w.request(w.token(nil), nil))
	refused(t, err, Unavailable)
	eq(t, 503, err.Status())
	eq(t, "", err.SignatureError())
}

func TestError_StatusAndSignatureError(t *testing.T) {
	e := fail(InvalidSignature, ReasonReplay)
	eq(t, 401, e.Status())
	eq(t, "error=invalid_signature", e.SignatureError())
	eq(t, `error=invalid_input, required_input=("@method" "@path")`, (&Error{Code: InvalidInput, Required: []string{"@method", "@path"}}).SignatureError())
	isFalse(t, strings.Contains(e.SignatureError(), "replay"), "the reason is for the operator, not the client")
}

func TestVerifierConfig(t *testing.T) {
	w := newWorld(t)
	_, err := NewVerifier(Config{Window: 10 * time.Minute}, w.trust, w.dir, w.replay, nil)
	isTrue(t, err != nil, "a window above five minutes is refused")
	_, err = NewVerifier(Config{}, nil, w.dir, w.replay, nil)
	isTrue(t, err != nil, "trust is required")
}

func TestVerify_AFailureNamesTheIssuerOnlyWhenTheTenantDeclaredIt(t *testing.T) {
	w := newWorld(t)
	// a declared provider whose agent fails later (a bad signature): the failure is about a provider the tenant trusts
	req := w.request(w.token(nil), nil)
	req.Path = "/v1/other"
	_, err := w.verify(req)
	refused(t, err, InvalidSignature)
	eq(t, testHost, err.Issuer)
	// an undeclared provider: nothing a stranger claimed is ever reported
	delete(w.trust, testHost)
	_, err = w.verify(w.request(w.token(nil), nil))
	refused(t, err, UnknownIssuer)
	eq(t, "", err.Issuer)
	// before the token is read at all
	_, err = w.verify(Request{Method: "GET", Authority: testAuthHdr, Path: "/", Header: http.Header{}})
	refused(t, err, InvalidRequest)
	eq(t, "", err.Issuer)
}
