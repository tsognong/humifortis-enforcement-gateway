package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type Context struct {
	TenantID      string
	Subject       string
	SessionID     string
	DeviceID      string
	SourceIP      string
	AuthMethod    string
	AuthAssurance string
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
	}
	if c.Subject == "" {
		c.Subject = r.Header.Get("X-User")
	}
	if c.TenantID == "" || c.Subject == "" {
		return Context{}, fmt.Errorf("tenant_id and subject are required")
	}
	return c, nil
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
