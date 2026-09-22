package state

import (
	"context"
	"testing"
	"time"
)

func TestMemoryConstraintExpires(t *testing.T) {
	store := NewMemory()
	key := "tenant:session"
	if err := store.Put(context.Background(), key, Constraint{Action: "BLOCK", ExpiresAt: time.Now().Add(20 * time.Millisecond)}); err != nil {
		t.Fatal(err)
	}
	value, err := store.Get(context.Background(), key)
	if err != nil || value == nil || value.Action != "BLOCK" {
		t.Fatalf("expected active constraint, value=%+v err=%v", value, err)
	}
	time.Sleep(30 * time.Millisecond)
	value, err = store.Get(context.Background(), key)
	if err != nil || value != nil {
		t.Fatalf("expected expired constraint, value=%+v err=%v", value, err)
	}
}

func TestMemoryReplayProtection(t *testing.T) {
	store := NewMemory()
	seen, err := store.Seen(context.Background(), "jti-1", time.Minute)
	if err != nil || seen {
		t.Fatalf("expected unseen event")
	}
	if err := store.MarkSeen(context.Background(), "jti-1", time.Minute); err != nil {
		t.Fatal(err)
	}
	seen, err = store.Seen(context.Background(), "jti-1", time.Minute)
	if err != nil || !seen {
		t.Fatalf("expected replay marker")
	}
}
