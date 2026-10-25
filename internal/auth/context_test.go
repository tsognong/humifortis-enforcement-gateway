package auth

import (
	"net"
	"net/http/httptest"
	"testing"
)

func TestFromRequestRejectsUnsignedHeaders(t *testing.T) {
	_, network, _ := net.ParseCIDR("127.0.0.1/32")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Tenant-ID", "tenant-a")
	r.Header.Set("X-Subject", "user-a")
	if _, err := FromRequest(r, "secret", []*net.IPNet{network}); err == nil {
		t.Fatal("expected signature validation failure")
	}
}

func TestFromRequestRequiresIdentity(t *testing.T) {
	_, network, _ := net.ParseCIDR("127.0.0.1/32")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	if _, err := FromRequest(r, "", []*net.IPNet{network}); err == nil {
		t.Fatal("expected missing identity failure")
	}
}

func TestFromRequestCarriesTheOriginalRequestWithoutItsQuery(t *testing.T) {
	_, network, _ := net.ParseCIDR("127.0.0.1/32")
	r := httptest.NewRequest("GET", "/_humifortis_auth", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Tenant-ID", "tenant-a")
	r.Header.Set("X-Subject", "user-a")
	r.Header.Set("X-Original-Method", "POST")
	r.Header.Set("X-Original-URI", "/orders/42?token=secret")
	c, err := FromRequest(r, "", []*net.IPNet{network})
	if err != nil {
		t.Fatal(err)
	}
	if c.Method != "POST" || c.Path != "/orders/42" {
		t.Fatalf("method and path without the query string, got %q %q", c.Method, c.Path)
	}
}

func TestTheHeaderPathCannotMintAVerifiedAgent(t *testing.T) {
	_, network, _ := net.ParseCIDR("127.0.0.1/32")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Tenant-ID", "tenant-a")
	r.Header.Set("X-Subject", "agent:aauth:planner@agents.example.com")
	if _, err := FromRequest(r, "", []*net.IPNet{network}); err == nil {
		t.Fatal("a header must never claim an identity the verifier mints")
	}
	r.Header.Set("X-Subject", "agent:keycloak:corp:bot")
	if _, err := FromRequest(r, "", []*net.IPNet{network}); err != nil {
		t.Fatalf("the other namespaces are unchanged: %v", err)
	}
}

func TestAAuthRequestIsTheOriginalRequestFromATrustedProxyOnly(t *testing.T) {
	_, network, _ := net.ParseCIDR("127.0.0.1/32")
	r := httptest.NewRequest("POST", "/_humifortis_auth", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Original-Method", "POST")
	r.Header.Set("X-Original-URI", "/v1/things?id=7")
	r.Header.Set("X-Original-Host", "api.example.com")
	r.Header.Set("X-Original-Scheme", "https")
	r.Header.Set("X-Real-IP", "203.0.113.5")
	r.Header.Set("Signature-Key", `sig=jwt;jwt="x"`)
	r.Header.Set("X-Tenant-ID", "tenant-evil")
	r.Header.Set("X-Subject", "someone")
	req, ip, err := AAuthRequest(r, []*net.IPNet{network})
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || req.Path != "/v1/things" || req.Query != "id=7" || req.Authority != "api.example.com" || req.Scheme != "https" || ip != "203.0.113.5" {
		t.Fatalf("request: %+v ip=%s", req, ip)
	}
	if req.Header.Get("X-Tenant-ID") != "" || req.Header.Get("X-Subject") != "" {
		t.Fatal("nothing about the tenant or the subject reaches the verifier")
	}
	if !HasAAuthProof(r) {
		t.Fatal("the Signature-Key field marks an AAuth request")
	}
	r.RemoteAddr = "198.51.100.9:1"
	if _, _, err := AAuthRequest(r, []*net.IPNet{network}); err == nil {
		t.Fatal("only a trusted proxy may speak for the client")
	}
}
