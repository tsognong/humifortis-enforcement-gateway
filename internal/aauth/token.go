package aauth

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

const (
	// TypAgentToken is the JWT typ of an agent token (media type aa-agent+jwt).
	TypAgentToken = "aa-agent+jwt"
	// DWKAgent is the well-known document name an agent provider publishes (the dwk claim).
	DWKAgent = "aauth-agent.json"

	maxTokenBytes = 8 << 10
)

// jwsHeader is the protected header of an agent token.
type jwsHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// AgentClaims are the claims of an agent token that the profile reads (draft 5.2.2). Time claims are NumericDate seconds.
type AgentClaims struct {
	Iss string `json:"iss"`
	Dwk string `json:"dwk"`
	Sub string `json:"sub"`
	Jti string `json:"jti"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Cnf struct {
		JWK json.RawMessage `json:"jwk"`
	} `json:"cnf"`
	PS          string `json:"ps,omitempty"`
	ParentAgent string `json:"parent_agent,omitempty"`
}

// agentToken is a parsed, NOT yet verified, agent token: its header and claims are what a stranger sent. Nothing in it is a fact
// until the signature over signingInput has been checked with a key of the issuer.
type agentToken struct {
	header       jwsHeader
	claims       AgentClaims
	signingInput []byte
	signature    []byte
}

// localPartRe and the AAuth agent identifier grammar of the profile: aauth:<local>@<domain>. The local part is restricted so that
// two spellings can never be two agents and no identifier needs encoding.
var localPartRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ParseAgentIdentifier splits aauth:local@domain (the sub of an agent token), checks the grammar and returns the local part and
// the lower-cased domain.
func ParseAgentIdentifier(sub string) (local, domain string, ok bool) {
	rest, found := strings.CutPrefix(sub, "aauth:")
	if !found {
		return "", "", false
	}
	at := strings.LastIndexByte(rest, '@')
	if at <= 0 || at == len(rest)-1 {
		return "", "", false
	}
	local, domain = rest[:at], strings.ToLower(rest[at+1:])
	if !localPartRe.MatchString(local) {
		return "", "", false
	}
	if _, err := validHost(domain); err != nil {
		return "", "", false
	}
	return local, domain, true
}

// issuerHost is the host of an issuer URL, which must be a bare https origin: no port, path, query, user information or fragment.
func issuerHost(iss string) (string, bool) {
	u, err := url.Parse(iss)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Port() != "" {
		return "", false
	}
	if strings.HasSuffix(iss, "/") {
		return "", false // the issuer is compared byte for byte with the metadata's: no trailing slash
	}
	host, err := validHost(u.Hostname())
	if err != nil {
		return "", false
	}
	return host, true
}

// parseAgentToken splits and decodes a compact JWS. It enforces the size bound, typ and the algorithm allow-list; it verifies
// nothing.
func parseAgentToken(raw string) (*agentToken, *Error) {
	if len(raw) == 0 || len(raw) > maxTokenBytes {
		return nil, failDetail(InvalidJWT, "the agent token is empty or too large")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, failDetail(InvalidJWT, "the agent token is not a compact JWS")
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, failDetail(InvalidJWT, "the token header is not base64url")
	}
	pay, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, failDetail(InvalidJWT, "the token payload is not base64url")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) == 0 {
		return nil, failDetail(InvalidJWT, "the token signature is missing")
	}
	t := &agentToken{signingInput: []byte(parts[0] + "." + parts[1]), signature: sig}
	if err := json.Unmarshal(hdr, &t.header); err != nil {
		return nil, failDetail(InvalidJWT, "the token header is not JSON")
	}
	if t.header.Typ != TypAgentToken {
		return nil, failDetail(InvalidJWT, "typ is not aa-agent+jwt")
	}
	switch t.header.Alg {
	case AlgEd25519, AlgES256:
	default:
		// none, the polymorphic EdDSA, HS* and every other identifier: refused before any key is looked up
		return nil, failDetail(UnsupportedAlgorithm, "the token algorithm is not Ed25519 or ES256")
	}
	if t.header.Kid == "" {
		return nil, failDetail(InvalidJWT, "the token has no kid")
	}
	if err := json.Unmarshal(pay, &t.claims); err != nil {
		return nil, failDetail(InvalidJWT, "the token payload is not JSON")
	}
	return t, nil
}
