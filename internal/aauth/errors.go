// Package aauth verifies an AAuth request (docs/aauth-agent.spec.md in humifortis-core): an HTTP Message Signature (RFC 9421) made with the
// key an agent token binds, an agent token issued by a provider the tenant trusts, and the replay, revocation and suspension checks
// around them. It is a pure verification step: it holds no risk logic and never calls Humifortis.
//
// The profile implemented is AAUTH-H1 of draft-hardt-oauth-aauth-protocol-10 (identity-based mode, scheme=jwt, agent token only).
// Anything outside it is refused explicitly, never interpreted loosely.
package aauth

import (
	"fmt"
	"strings"
)

// Code is the machine-readable reason a request was refused. The values are those of the draft's verification taxonomy
// (section 12.8.4) plus unknown_issuer (the tenant does not trust the provider).
type Code string

const (
	InvalidRequest       Code = "invalid_request"
	InvalidInput         Code = "invalid_input"
	InvalidSignature     Code = "invalid_signature"
	UnsupportedScheme    Code = "unsupported_scheme"
	InvalidKey           Code = "invalid_key"
	UnknownKey           Code = "unknown_key"
	InvalidJWT           Code = "invalid_jwt"
	ExpiredJWT           Code = "expired_jwt"
	IssuerMissing        Code = "issuer_missing"
	IssuerMismatch       Code = "issuer_mismatch"
	UnsupportedAlgorithm Code = "unsupported_algorithm"
	UnknownIssuer        Code = "unknown_issuer"
	// Unavailable is not a verdict on the request: a dependency the verifier cannot do without (the replay store) failed.
	// The request is refused all the same (fail closed), with a distinct code for the operator.
	Unavailable Code = "unavailable"
)

// Reason refines a Code for the operator (never sent to the client, never carries a claim of the request).
type Reason string

const (
	ReasonReplay         Reason = "replay"
	ReasonRevoked        Reason = "revoked"
	ReasonSuspended      Reason = "suspended"
	ReasonClockSkew      Reason = "created_outside_window"
	ReasonUncovered      Reason = "required_component_not_covered"
	ReasonPinnedKey      Reason = "key_not_pinned"
	ReasonLifetime       Reason = "token_lifetime_too_long"
	ReasonNotYetValid    Reason = "token_not_yet_valid"
	ReasonSubjectGrammar Reason = "agent_identifier_invalid"
	ReasonKeyBinding     Reason = "cnf_key_is_not_the_signing_key"
)

// Error is a refusal.
type Error struct {
	Code   Code
	Reason Reason
	// Required lists the components a signature must cover (invalid_input only).
	Required []string
	Detail   string
	// Issuer is the provider host, set ONLY when the tenant declared it (the failure is then about a provider it trusts). A host
	// that a stranger claimed is never here.
	Issuer string
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Detail)
	}
	if e.Reason != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Reason)
	}
	return string(e.Code)
}

// Status is the HTTP status of the refusal: every verification failure is a 401 (draft 12.8.4); a failed dependency is a 503
// the client may retry.
func (e *Error) Status() int {
	if e.Code == Unavailable {
		return 503
	}
	return 401
}

// SignatureError is the value of the Signature-Error response header: a structured-field dictionary (error=<code>, and
// required_input=("@method" ...) for invalid_input). It names the verdict and nothing about the tenant or the claims.
func (e *Error) SignatureError() string {
	if e.Code == Unavailable {
		return ""
	}
	out := "error=" + string(e.Code)
	if e.Code == InvalidInput && len(e.Required) > 0 {
		quoted := make([]string, len(e.Required))
		for i, c := range e.Required {
			quoted[i] = `"` + c + `"`
		}
		out += ", required_input=(" + strings.Join(quoted, " ") + ")"
	}
	return out
}

func fail(code Code, reason Reason) *Error       { return &Error{Code: code, Reason: reason} }
func failDetail(code Code, detail string) *Error { return &Error{Code: code, Detail: detail} }
func failReason(code Code, reason Reason, d string) *Error {
	return &Error{Code: code, Reason: reason, Detail: d}
}
