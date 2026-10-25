package aauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// The algorithms of the profile. The draft requires Ed25519 and recommends ES256; an algorithm identifier that does not name
// one curve and one hash (the polymorphic "EdDSA", "none", HS*) is refused (section 12.8.1).
const (
	AlgEd25519 = "Ed25519"
	AlgES256   = "ES256"
)

// JWK is the public key of an agent or of a provider (RFC 7517), restricted to what the profile accepts.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
}

// Parsed is a public key ready to verify with.
type parsedKey struct {
	alg string
	pub crypto.PublicKey
}

// key checks that the JWK is a complete public key whose alg is fully specified and agrees with kty and crv, and builds it. A
// private member (d) is refused: a public document that carries one is a leak the verifier must not paper over.
func (k JWK) key() (parsedKey, *Error) {
	switch {
	case k.Alg == "":
		return parsedKey{}, failDetail(InvalidKey, "the key has no alg: it must be fully specified")
	case k.Alg != AlgEd25519 && k.Alg != AlgES256:
		return parsedKey{}, failDetail(UnsupportedAlgorithm, "the key algorithm is not Ed25519 or ES256")
	}
	switch k.Alg {
	case AlgEd25519:
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			return parsedKey{}, failDetail(InvalidKey, "kty and crv do not agree with alg Ed25519")
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return parsedKey{}, failDetail(InvalidKey, "an Ed25519 key is 32 bytes")
		}
		return parsedKey{alg: AlgEd25519, pub: ed25519.PublicKey(x)}, nil
	default:
		if k.Kty != "EC" || k.Crv != "P-256" {
			return parsedKey{}, failDetail(InvalidKey, "kty and crv do not agree with alg ES256")
		}
		x, errX := base64.RawURLEncoding.DecodeString(k.X)
		y, errY := base64.RawURLEncoding.DecodeString(k.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			return parsedKey{}, failDetail(InvalidKey, "an ES256 key has two 32-byte coordinates")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if _, err := pub.ECDH(); err != nil { // not on the curve
			return parsedKey{}, failDetail(InvalidKey, "the point is not on the curve")
		}
		return parsedKey{alg: AlgES256, pub: pub}, nil
	}
}

// UnmarshalJWK reads a JWK, refusing a private member and unknown shapes.
func UnmarshalJWK(raw []byte) (JWK, *Error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return JWK{}, failDetail(InvalidKey, "the key is not a JSON object")
	}
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
		if _, has := probe[private]; has {
			return JWK{}, failDetail(InvalidKey, "the key document carries a private member")
		}
	}
	var k JWK
	if err := json.Unmarshal(raw, &k); err != nil {
		return JWK{}, failDetail(InvalidKey, "the key is not a JWK")
	}
	return k, nil
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint of the key, base64url without padding: the stable name of a key.
func (k JWK) Thumbprint() (string, *Error) {
	var canonical string
	switch k.Kty {
	case "OKP":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q}`, k.Crv, k.Kty, k.X)
	case "EC":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, k.Crv, k.Kty, k.X, k.Y)
	default:
		return "", failDetail(InvalidKey, "unsupported key type")
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// verify checks a signature made with the key over msg: Ed25519 over the bytes, ES256 over their SHA-256 with the signature as
// r||s (64 bytes), as RFC 9421 and JWS (RFC 7518 3.4) both write it.
func (p parsedKey) verify(msg, sig []byte) bool {
	switch p.alg {
	case AlgEd25519:
		return len(sig) == ed25519.SignatureSize && ed25519.Verify(p.pub.(ed25519.PublicKey), msg, sig)
	case AlgES256:
		if len(sig) != 64 {
			return false
		}
		digest := sha256.Sum256(msg)
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(p.pub.(*ecdsa.PublicKey), digest[:], r, s)
	}
	return false
}
