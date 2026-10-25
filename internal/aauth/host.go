package aauth

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode"
)

var hostLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// validHost normalises a host name the way the tenant's provider list does (humifortis-core domain.NormalizeIssuerHost): lower
// case, ASCII only, a fully qualified name, never an address. Both sides must agree byte for byte, or a provider the tenant
// trusts would not match the issuer that signs.
func validHost(raw string) (string, error) {
	h := strings.TrimSpace(raw)
	if h == "" || strings.ContainsAny(h, "/:@?#[]*% \t") {
		return "", fmt.Errorf("not a host")
	}
	for _, r := range h {
		if r > unicode.MaxASCII {
			return "", fmt.Errorf("not an ASCII host")
		}
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if len(h) > 253 || net.ParseIP(h) != nil {
		return "", fmt.Errorf("not a host name")
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("not fully qualified")
	}
	for _, l := range labels {
		if !hostLabelRe.MatchString(l) {
			return "", fmt.Errorf("invalid label")
		}
	}
	return h, nil
}
