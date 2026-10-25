package aauth

import (
	"encoding/base64"
	"net/http"
	"testing"
)

// The Ed25519 test key of RFC 9421 appendix B.1.4 and the signature of B.2.6, "Signing a Request Using ed25519".
const (
	rfcKeyX           = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
	rfcSignatureInput = `sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`
	rfcSignature      = `sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:`
)

// The request of appendix B.2 (the body is not covered by this signature).
func rfcRequest() Request {
	h := http.Header{}
	h.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", "18")
	return Request{Method: "POST", Authority: "example.com", Path: "/foo", Query: "param=Value&Pet=dog", Scheme: "https", Header: h}
}

// The signature base of B.2.6, byte for byte.
const rfcSignatureBase = "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n" +
	"\"@method\": POST\n" +
	"\"@path\": /foo\n" +
	"\"@authority\": example.com\n" +
	"\"content-type\": application/json\n" +
	"\"content-length\": 18\n" +
	"\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\""

func TestRFC9421_AppendixB26_SignatureBaseIsByteExact(t *testing.T) {
	in, err := parseSignatureInput([]string{rfcSignatureInput}, "sig-b26")
	noFail(t, err)
	eq(t, []string{"date", "@method", "@path", "@authority", "content-type", "content-length"}, in.components)
	isTrue(t, in.hasCreated && in.created == 1618884473, "created")
	isTrue(t, in.hasKeyID, "keyid")

	base, err := signatureBase(rfcRequest(), in)
	noFail(t, err)
	eq(t, rfcSignatureBase, base)
}

func TestRFC9421_AppendixB26_TheEd25519SignatureVerifies(t *testing.T) {
	in, err := parseSignatureInput([]string{rfcSignatureInput}, "sig-b26")
	noFail(t, err)
	base, err := signatureBase(rfcRequest(), in)
	noFail(t, err)

	dict, perr := parseDictionary(rfcSignature)
	noErr(t, perr)
	eq(t, 1, len(dict))
	eq(t, kindBytes, dict[0].item.kind)

	key, kerr := JWK{Kty: "OKP", Crv: "Ed25519", X: rfcKeyX, Alg: AlgEd25519}.key()
	noFail(t, kerr)
	isTrue(t, key.verify([]byte(base), dict[0].item.raw), "the signature of the RFC verifies with its public key")

	tampered := []byte(base)
	tampered[len(tampered)-5] ^= 1
	isFalse(t, key.verify(tampered, dict[0].item.raw), "one changed byte does not")

	other := rfcRequest()
	other.Path = "/bar"
	otherBase, _ := signatureBase(other, in)
	isFalse(t, key.verify([]byte(otherBase), dict[0].item.raw), "another path does not")
}

func TestThumbprint_RFC8037AppendixA3(t *testing.T) {
	// RFC 8037 appendix A.3: the thumbprint of the Ed25519 key with this x
	k := JWK{Kty: "OKP", Crv: "Ed25519", X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", Alg: AlgEd25519}
	got, err := k.Thumbprint()
	noFail(t, err)
	eq(t, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", got)

	rfc := JWK{Kty: "OKP", Crv: "Ed25519", X: rfcKeyX, Alg: AlgEd25519}
	a, _ := rfc.Thumbprint()
	raw, derr := base64.RawURLEncoding.DecodeString(a)
	noErr(t, derr)
	eq(t, 32, len(raw))
	isTrue(t, a != got, "two keys, two thumbprints")
}
