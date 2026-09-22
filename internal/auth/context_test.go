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
