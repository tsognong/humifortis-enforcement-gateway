package humifortis

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestReporterSendsOnePerIssuerAndCodeInTheWindow(t *testing.T) {
	var mu sync.Mutex
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		got = append(got, b["event"].(map[string]any))
		mu.Unlock()
		w.WriteHeader(202)
	}))
	defer srv.Close()
	rep := NewReporter(NewClient(srv.URL, "k", time.Second), time.Minute)
	now := time.Now()
	rep.now = func() time.Time { return now }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rep.Run(ctx)

	for i := 0; i < 50; i++ {
		rep.Report(ProofRejected{Issuer: "agents.example.com", Code: "invalid_signature", SourceIP: "203.0.113.1"})
	}
	rep.Report(ProofRejected{Code: "unknown_issuer"})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || rep.Dropped.Load() != 49 {
		t.Fatalf("sent=%d dropped=%d", len(got), rep.Dropped.Load())
	}
	if got[0]["event_type"] != "aauth_proof_rejected" || got[0]["metadata"].(map[string]any)["failure_code"] != "invalid_signature" {
		t.Fatalf("event: %v", got[0])
	}
}

func TestReporterFailureIsCountedNeverRaised(t *testing.T) {
	rep := NewReporter(NewClient("http://127.0.0.1:1", "k", 50*time.Millisecond), time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rep.Run(ctx)
	rep.Report(ProofRejected{Code: "invalid_signature"})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && rep.Failed.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if rep.Failed.Load() != 1 {
		t.Fatal("a failed report is counted")
	}
}
