package aauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// ProviderPolicy is what the tenant declared about a provider it trusts (humifortis-core agent_providers).
type ProviderPolicy struct {
	// Trust is the level the tenant gave (enterprise | partner); informational here, a feature of the decision in Core.
	Trust string
	// PinnedJKT, when not empty, restricts the signing keys accepted from the provider (RFC 7638 thumbprints).
	PinnedJKT []string
	// MaxTokenLifetime caps exp-iat of an agent token (the draft's 24 hours at most).
	MaxTokenLifetime time.Duration
	// FreshToken is how recent iat must be for the token to count as fresh.
	FreshToken time.Duration
}

// TrustSource answers whether the tenant trusts a provider. An issuer that is not declared is NOT trusted (default deny). It is
// consulted BEFORE any fetch of the provider's metadata, so a stranger cannot make the verifier fetch a URL of his choosing.
type TrustSource interface {
	Provider(issuerHost string) (ProviderPolicy, bool)
}

// ReplayStore remembers a verified signature for the window. FirstUse marks the key and reports whether it had not been seen:
// one atomic operation (Redis SET NX PX), so two instances racing on the same request cannot both pass.
type ReplayStore interface {
	FirstUse(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

// RevocationStore holds what the issuer or an analyst revoked. It is optional (nil = nothing is revoked).
type RevocationStore interface {
	Revoked(ctx context.Context, issuer, jti string) (bool, error)
}

// Config of the verifier.
type Config struct {
	// TenantID prefixes every replay key: the tenant is the gateway's, never the request's.
	TenantID string
	// Window is how far from now the created parameter may be (default 60 s; the draft's default, never more than 5 minutes).
	Window time.Duration
	// Skew tolerated for iat/created in the future (default 5 s).
	Skew time.Duration
}

// Verifier verifies AAuth requests. Safe for concurrent use.
type Verifier struct {
	cfg     Config
	trust   TrustSource
	keys    KeyDirectory
	replay  ReplayStore
	revoked RevocationStore
	now     func() time.Time
}

// NewVerifier builds a verifier. keys, trust and replay are required.
func NewVerifier(cfg Config, trust TrustSource, keys KeyDirectory, replay ReplayStore, revoked RevocationStore) (*Verifier, error) {
	if trust == nil || keys == nil || replay == nil {
		return nil, fmt.Errorf("aauth: trust, keys and replay are required")
	}
	if cfg.Window <= 0 {
		cfg.Window = 60 * time.Second
	}
	if cfg.Window > 5*time.Minute {
		return nil, fmt.Errorf("aauth: the signature window cannot exceed 5 minutes")
	}
	if cfg.Skew <= 0 {
		cfg.Skew = 5 * time.Second
	}
	return &Verifier{cfg: cfg, trust: trust, keys: keys, replay: replay, revoked: revoked, now: time.Now}, nil
}

// WithClock is for tests.
func (v *Verifier) WithClock(now func() time.Time) *Verifier {
	v.now = now
	return v
}

// Verified is the outcome of a successful verification: what the gateway may tell Core. Everything in it was checked in this
// request; nothing is a claim the signature chain did not cover.
type Verified struct {
	// AgentID is the entity id: agent:aauth:<local>@<domain>.
	AgentID string
	// Sub is the protocol identifier: aauth:<local>@<domain>.
	Sub string
	// Issuer is the host of the agent provider.
	Issuer string
	// Trust is the level the tenant declared for the provider.
	Trust string
	// JKT is the RFC 7638 thumbprint of the signing key and KeyAlg its algorithm.
	JKT, KeyAlg string
	// TokenID is the jti of the agent token, TokenIssuedAt and TokenExpiresAt its times.
	TokenID                       string
	TokenIssuedAt, TokenExpiresAt time.Time
	// TokenFresh: the token was issued within the provider's freshness window.
	TokenFresh bool
	// SignatureCreated is the created parameter; Covered the components the signature covers.
	SignatureCreated time.Time
	Covered          []string
	// ProviderURL of the person server named by the token (asserted by the provider, verified as part of the token), if any.
	PS          string
	ParentAgent string
	// ReplayKey is the key the signature was recorded under (a hash; for audit correlation, never the signature itself).
	ReplayKey string
}

// Verify runs the verification procedure of docs/aauth-agent.spec.md §12.1: each step is a gate, the first failure stops, and
// nothing a stranger claimed is read before the signature chain passed.
func (v *Verifier) Verify(ctx context.Context, req Request) (*Verified, *Error) {
	var declared string
	out, err := v.verify(ctx, req, &declared)
	if err != nil {
		err.Issuer = declared
	}
	return out, err
}

func (v *Verifier) verify(ctx context.Context, req Request, declared *string) (*Verified, *Error) {
	now := v.now()

	// 2. the three fields
	sigFields, inputFields, keyFields := req.Header.Values("Signature"), req.Header.Values("Signature-Input"), req.Header.Values("Signature-Key")
	if len(sigFields) == 0 || len(inputFields) == 0 || len(keyFields) == 0 {
		return nil, failDetail(InvalidRequest, "Signature, Signature-Input and Signature-Key are required")
	}
	sigDict, err := parseDictionary(combineField(sigFields))
	if err != nil || len(sigDict) != 1 || sigDict[0].inner || sigDict[0].item.kind != kindBytes {
		return nil, failDetail(InvalidRequest, "Signature carries exactly one signature")
	}
	label, signature := sigDict[0].key, sigDict[0].item.raw
	in, perr := parseSignatureInput(inputFields, label)
	if perr != nil {
		return nil, perr
	}

	// 5. the key scheme: jwt only
	keyDict, err := parseDictionary(combineField(keyFields))
	if err != nil {
		return nil, failDetail(InvalidRequest, "Signature-Key is not a structured field")
	}
	var keyMember *member
	for i := range keyDict {
		if keyDict[i].key == label {
			keyMember = &keyDict[i]
		}
	}
	if keyMember == nil || keyMember.inner {
		return nil, failDetail(InvalidRequest, "Signature-Key has no key for the signature")
	}
	if keyMember.item.kind != kindToken || keyMember.item.str != "jwt" {
		return nil, failDetail(UnsupportedScheme, "only scheme=jwt is accepted")
	}
	jwtParam, ok := findParam(keyMember.params, "jwt")
	if !ok || jwtParam.kind != kindString {
		return nil, failDetail(InvalidRequest, "the jwt scheme carries the token in its jwt parameter")
	}

	// 3. covered components (the field itself is covered: a different token cannot be swapped in)
	authorization := hasAAuthCredential(req)
	required := requiredComponents(authorization)
	if missing := missingComponents(in.components, required); len(missing) > 0 {
		return nil, &Error{Code: InvalidInput, Reason: ReasonUncovered, Required: required, Detail: "not covered: " + strings.Join(missing, ", ")}
	}

	// 4. parameters and the window
	if !in.hasCreated {
		return nil, failDetail(InvalidRequest, "the signature has no created parameter")
	}
	if in.hasAlg {
		return nil, failDetail(InvalidRequest, "the alg parameter must not be sent")
	}
	created := time.Unix(in.created, 0)
	if d := now.Sub(created); d > v.cfg.Window || -d > v.cfg.Skew {
		return nil, fail(InvalidSignature, ReasonClockSkew)
	}
	if in.hasExpires && now.After(time.Unix(in.expires, 0).Add(v.cfg.Skew)) {
		return nil, fail(InvalidSignature, ReasonClockSkew)
	}

	// 6. the agent token: shape, identifier, issuer, times (nothing is trusted yet)
	tok, terr := parseAgentToken(jwtParam.str)
	if terr != nil {
		return nil, terr
	}
	local, domain, ok := ParseAgentIdentifier(tok.claims.Sub)
	if !ok {
		return nil, fail(InvalidJWT, ReasonSubjectGrammar)
	}
	host, ok := issuerHost(tok.claims.Iss)
	if !ok {
		return nil, failDetail(IssuerMismatch, "iss is not a bare https origin")
	}
	if host != domain {
		return nil, failDetail(IssuerMismatch, "iss is not the domain of the agent identifier")
	}
	if tok.claims.Dwk != DWKAgent {
		return nil, failDetail(InvalidJWT, "dwk is not aauth-agent.json")
	}
	if tok.claims.Jti == "" || len(tok.claims.Jti) > 256 {
		return nil, failDetail(InvalidJWT, "jti is missing")
	}
	issuedAt, expiresAt := time.Unix(tok.claims.Iat, 0), time.Unix(tok.claims.Exp, 0)
	if tok.claims.Iat <= 0 || tok.claims.Exp <= 0 {
		return nil, failDetail(InvalidJWT, "iat and exp are required")
	}
	if !expiresAt.After(now) {
		return nil, fail(ExpiredJWT, "")
	}
	if issuedAt.After(now.Add(v.cfg.Skew)) {
		return nil, fail(InvalidJWT, ReasonNotYetValid)
	}

	// 7. trust: BEFORE any fetch
	policy, trusted := v.trust.Provider(host)
	if !trusted {
		return nil, failDetail(UnknownIssuer, "the tenant does not trust this provider")
	}
	*declared = host // the tenant named it: the only issuer that may be reported when a later step fails
	maxLife := 24 * time.Hour
	if policy.MaxTokenLifetime > 0 && policy.MaxTokenLifetime < maxLife {
		maxLife = policy.MaxTokenLifetime
	}
	if expiresAt.Sub(issuedAt) > maxLife {
		return nil, fail(InvalidJWT, ReasonLifetime)
	}

	// 8. the provider's key, and the token's signature with it (one refresh on a cached key that fails)
	if tok.header.Alg == "" {
		return nil, failDetail(UnsupportedAlgorithm, "no token algorithm")
	}
	var verified bool
	for attempt := 0; attempt < 2 && !verified; attempt++ {
		pk, kerr := v.keys.Key(ctx, host, tok.header.Kid, attempt == 1)
		if kerr != nil {
			if attempt == 0 && kerr.Code == UnknownKey {
				continue // maybe a silent re-keying: ask once more (the directory keeps its own floor)
			}
			return nil, kerr
		}
		parsed, perr := pk.key()
		if perr != nil {
			return nil, perr
		}
		if parsed.alg != tok.header.Alg {
			return nil, failDetail(InvalidJWT, "the token algorithm is not that of the key")
		}
		verified = parsed.verify(tok.signingInput, tok.signature)
	}
	if !verified {
		return nil, failDetail(InvalidJWT, "the token signature does not verify")
	}

	// 9. the key the token binds, and the HTTP signature with it
	if len(tok.claims.Cnf.JWK) == 0 {
		return nil, failDetail(InvalidKey, "the token binds no key (cnf.jwk)")
	}
	bound, berr := UnmarshalJWK(tok.claims.Cnf.JWK)
	if berr != nil {
		return nil, berr
	}
	boundKey, berr := bound.key()
	if berr != nil {
		return nil, berr
	}
	jkt, berr := bound.Thumbprint()
	if berr != nil {
		return nil, berr
	}
	if len(policy.PinnedJKT) > 0 && !contains(policy.PinnedJKT, jkt) {
		return nil, fail(UnknownKey, ReasonPinnedKey)
	}
	base, serr := signatureBase(req, in)
	if serr != nil {
		return nil, serr
	}
	if !boundKey.verify([]byte(base), signature) {
		return nil, fail(InvalidSignature, ReasonKeyBinding)
	}

	// 10. replay: only a request that PASSED is recorded, so an unauthenticated flood fills nothing
	sum := sha256.Sum256(append([]byte(v.cfg.TenantID+"\x00"), signature...))
	replayKey := "aauth:sig:" + hex.EncodeToString(sum[:])
	first, rerr := v.replay.FirstUse(ctx, replayKey, v.cfg.Window+v.cfg.Skew+time.Second)
	if rerr != nil {
		return nil, failDetail(Unavailable, "the replay store is not available")
	}
	if !first {
		return nil, fail(InvalidSignature, ReasonReplay)
	}

	// 11. revocation
	if v.revoked != nil {
		gone, err := v.revoked.Revoked(ctx, tok.claims.Iss, tok.claims.Jti)
		if err != nil {
			return nil, failDetail(Unavailable, "the revocation list is not available")
		}
		if gone {
			return nil, fail(InvalidJWT, ReasonRevoked)
		}
	}

	freshFor := policy.FreshToken
	if freshFor <= 0 {
		freshFor = 5 * time.Minute
	}
	covered := append([]string(nil), in.components...)
	return &Verified{
		AgentID: "agent:aauth:" + local + "@" + domain, Sub: tok.claims.Sub, Issuer: host, Trust: policy.Trust,
		JKT: jkt, KeyAlg: boundKey.alg, TokenID: tok.claims.Jti, TokenIssuedAt: issuedAt, TokenExpiresAt: expiresAt,
		TokenFresh: now.Sub(issuedAt) <= freshFor, SignatureCreated: created, Covered: covered,
		PS: tok.claims.PS, ParentAgent: tok.claims.ParentAgent, ReplayKey: replayKey,
	}, nil
}

// hasAAuthCredential reports whether the request presents an AAuth access credential, which the signature must then cover.
func hasAAuthCredential(req Request) bool {
	if req.Header.Get("AAuth-Access") != "" {
		return true
	}
	scheme, _, _ := strings.Cut(strings.TrimSpace(req.Header.Get("Authorization")), " ")
	return strings.EqualFold(scheme, "AAuth")
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
