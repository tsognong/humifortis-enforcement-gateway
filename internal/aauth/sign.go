package aauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// A reference signer for the agent and the provider sides of the profile. The gateway never signs a request; this is what the
// conformance tests and the e2e client use to produce requests the verifier must accept or refuse, and it documents the exact
// wire form of AAUTH-H1.

// Key is an Ed25519 key pair with the public JWK it publishes.
type Key struct {
	Private ed25519.PrivateKey
	JWK     JWK
}

// NewKey creates a key pair; kid is the key id the JWK carries (the provider's keys need one).
func NewKey(kid string) Key {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return Key{Private: priv, JWK: JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub), Alg: AlgEd25519, Kid: kid}}
}

// Thumbprint of the public key.
func (k Key) Thumbprint() string {
	t, err := k.JWK.Thumbprint()
	if err != nil {
		panic(err)
	}
	return t
}

// TokenSpec is what a provider puts in an agent token.
type TokenSpec struct {
	Issuer      string // https://agents.example.com
	Subject     string // aauth:planner@agents.example.com
	ID          string // jti
	Agent       JWK    // the key the token binds (cnf.jwk)
	IssuedAt    time.Time
	ExpiresAt   time.Time
	Typ         string // default aa-agent+jwt
	Alg         string // default Ed25519
	Dwk         string // default aauth-agent.json
	PS          string
	ParentAgent string
}

// IssueAgentToken signs an agent token with the provider key.
func (k Key) IssueAgentToken(s TokenSpec) string {
	typ, alg, dwk := s.Typ, s.Alg, s.Dwk
	if typ == "" {
		typ = TypAgentToken
	}
	if alg == "" {
		alg = AlgEd25519
	}
	if dwk == "" {
		dwk = DWKAgent
	}
	header, _ := json.Marshal(map[string]string{"typ": typ, "alg": alg, "kid": k.JWK.Kid})
	cnf := map[string]any{"jwk": s.Agent}
	claims := map[string]any{"iss": s.Issuer, "dwk": dwk, "sub": s.Subject, "jti": s.ID, "iat": s.IssuedAt.Unix(), "exp": s.ExpiresAt.Unix(), "cnf": cnf}
	if s.PS != "" {
		claims["ps"] = s.PS
	}
	if s.ParentAgent != "" {
		claims["parent_agent"] = s.ParentAgent
	}
	payload, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(k.Private, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// SignOptions of a request signature.
type SignOptions struct {
	Created time.Time
	// Covered is the list of components (default: the required ones). Header fields are lower case.
	Covered []string
	// Label of the signature (default "sig").
	Label string
}

// SignRequest adds Signature-Key, Signature-Input and Signature to the headers: the agent signs the request with its key, and
// presents its agent token (RFC 9421 and the draft's scheme=jwt).
func SignRequest(h http.Header, method, authority, path, query, scheme string, agent Key, agentToken string, opt SignOptions) {
	label := opt.Label
	if label == "" {
		label = "sig"
	}
	covered := opt.Covered
	if len(covered) == 0 {
		covered = []string{"@method", "@authority", "@path", "signature-key"}
	}
	h.Set("Signature-Key", label+`=jwt;jwt="`+agentToken+`"`)
	quoted := make([]string, len(covered))
	for i, c := range covered {
		quoted[i] = `"` + c + `"`
	}
	raw := "(" + strings.Join(quoted, " ") + ");created=" + strconv.FormatInt(opt.Created.Unix(), 10)
	h.Set("Signature-Input", label+"="+raw)
	in := signatureInput{label: label, components: covered, raw: raw}
	base, err := signatureBase(Request{Method: method, Authority: authority, Path: path, Query: query, Scheme: scheme, Header: h}, in)
	if err != nil {
		panic(err)
	}
	sig := ed25519.Sign(agent.Private, []byte(base))
	h.Set("Signature", label+"=:"+base64.StdEncoding.EncodeToString(sig)+":")
}
