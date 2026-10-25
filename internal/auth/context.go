package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/tsognong/humifortis-enforcement-gateway/internal/aauth"
)

type Context struct {
	TenantID      string
	Subject       string
	SessionID     string
	DeviceID      string
	SourceIP      string
	AuthMethod    string
	AuthAssurance string
	// Method and Path are the request being authorised (nginx auth_request: X-Original-Method, X-Original-URI).
	Method string
	Path   string
}

func FromRequest(r *http.Request, trustedSecret string, trustedProxies []*net.IPNet) (Context, error) {
	if !trustedSource(r.RemoteAddr, trustedProxies) {
		return Context{}, fmt.Errorf("request source is not a trusted proxy")
	}
	if trustedSecret != "" {
		provided := r.Header.Get("X-Humifortis-Trusted-Context")
		expected := sign(r, trustedSecret)
		if !hmac.Equal([]byte(provided), []byte(expected)) {
			return Context{}, fmt.Errorf("trusted context signature invalid")
		}
	}
	c := Context{
		TenantID: r.Header.Get("X-Tenant-ID"), Subject: r.Header.Get("X-Subject"), SessionID: r.Header.Get("X-Session-ID"),
		DeviceID: r.Header.Get("X-Device-ID"), SourceIP: clientIP(r), AuthMethod: r.Header.Get("X-Auth-Method"), AuthAssurance: r.Header.Get("X-Auth-Assurance"),
		Method: r.Header.Get("X-Original-Method"), Path: originalPath(r.Header.Get("X-Original-URI")),
	}
	if c.Subject == "" {
		c.Subject = r.Header.Get("X-User")
	}
	if strings.HasPrefix(c.Subject, "agent:aauth:") {
		// a verified agent is minted by the verifier from a proof, never by a header: this path cannot claim it (G4)
		return Context{}, fmt.Errorf("the namespace agent:aauth: is reserved to the AAuth verifier")
	}
	if c.TenantID == "" || c.Subject == "" {
		return Context{}, fmt.Errorf("tenant_id and subject are required")
	}
	return c, nil
}

// originalPath is the path of the original request without its query string (a query can carry secrets and is
// never part of what the decision is about).
func originalPath(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		uri = uri[:i]
	}
	return uri
}
func sign(r *http.Request, secret string) string {
	payload := strings.Join([]string{r.Header.Get("X-Tenant-ID"), r.Header.Get("X-Subject"), r.Header.Get("X-Session-ID"), r.Method, r.URL.RequestURI()}, "\x00")
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
func trustedSource(remote string, proxies []*net.IPNet) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	for _, network := range proxies {
		if ip != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
func clientIP(r *http.Request) string {
	if value := r.Header.Get("X-Real-IP"); value != "" {
		return value
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}
func ParseCIDRs(values []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy CIDR %q: %w", value, err)
		}
		out = append(out, network)
	}
	return out, nil
}

// HasAAuthProof reports whether the request presents an AAuth proof (the Signature-Key field of the profile). A request that
// does is judged by the AAuth path alone: it is never downgraded to the headers, to a Bearer token or to anonymous.
func HasAAuthProof(r *http.Request) bool {
	return len(r.Header.Values("Signature-Key")) > 0
}

// AAuthRequest is the request nginx asks the gateway to authorise, as the verifier needs it: method, authority (the Host the client
// signed), path and query of the ORIGINAL request, and the signature fields. Only a trusted proxy may speak for the client;
// nothing about the tenant or the subject is read from it (the tenant is the gateway's configuration).
func AAuthRequest(r *http.Request, trustedProxies []*net.IPNet) (aauth.Request, string, error) {
	if !trustedSource(r.RemoteAddr, trustedProxies) {
		return aauth.Request{}, "", fmt.Errorf("request source is not a trusted proxy")
	}
	uri := r.Header.Get("X-Original-URI")
	path, query := uri, ""
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		path, query = uri[:i], uri[i+1:]
	}
	h := http.Header{}
	for _, k := range []string{"Signature", "Signature-Input", "Signature-Key", "Content-Digest", "Content-Type", "Content-Length"} {
		if v := r.Header.Values(k); len(v) > 0 {
			h[http.CanonicalHeaderKey(k)] = v
		}
	}
	ip := clientIP(r)
	return aauth.Request{
		Method: r.Header.Get("X-Original-Method"), Authority: r.Header.Get("X-Original-Host"), Path: path, Query: query,
		Scheme: r.Header.Get("X-Original-Scheme"), Header: h, SourceIP: ip,
	}, ip, nil
}
