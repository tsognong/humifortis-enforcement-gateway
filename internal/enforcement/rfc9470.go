package enforcement

import (
	"fmt"
	"strconv"
	"strings"
)

// The standard form of a step-up for an API (RFC 9470, docs/sso-and-external-idp-e2e.spec.md, P13, AP-5): a resource server that
// needs a stronger sign-in than the token it received answers 401 with
//
//	WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="...", max_age=...
//
// and the client sends the person back to the authorization server with those acr_values. The gateway's CHALLENGE speaks it, so
// a client that follows the standard needs nothing of Humifortis.

// AcrForLevel is the acr value of an assurance level of the ladder (1 a code, 2 an app, 3 a phishing-resistant factor): the
// names a realm maps to its levels with Keycloak's acr.loa.map.
func AcrForLevel(level int) string {
	switch level {
	case 1:
		return "urn:humifortis:acr:code"
	case 2:
		return "urn:humifortis:acr:app"
	case 3:
		return "urn:humifortis:acr:key"
	}
	return ""
}

// ChallengeHeader is the WWW-Authenticate value of a CHALLENGE. requiredAssurance is what Humifortis answered: a level of the
// ladder ("2"), or the generic "MFA" (any second factor: level 1). maxAgeSeconds, when positive, asks for a fresh sign-in
// as well (the token is old, not weak).
func ChallengeHeader(requiredAssurance string, maxAgeSeconds int) string {
	level := 1
	if n, err := strconv.Atoi(strings.TrimSpace(requiredAssurance)); err == nil && n >= 1 {
		level = n
		if level > 3 {
			level = 3
		}
	}
	h := fmt.Sprintf(`Bearer error="insufficient_user_authentication", error_description="A stronger authentication is required", acr_values=%q`, AcrForLevel(level))
	if maxAgeSeconds > 0 {
		h += fmt.Sprintf(", max_age=%d", maxAgeSeconds)
	}
	return h
}
