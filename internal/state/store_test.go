package state

import (
	"context"
	"sync"
	"sync/atomic"
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
	first, err := store.FirstUse(context.Background(), "jti-1", time.Minute)
	if err != nil || !first {
		t.Fatalf("the first use is first")
	}
	first, err = store.FirstUse(context.Background(), "jti-1", time.Minute)
	if err != nil || first {
		t.Fatalf("the second use is a replay")
	}
	first, _ = store.FirstUse(context.Background(), "jti-2", 20*time.Millisecond)
	time.Sleep(40 * time.Millisecond)
	if again, _ := store.FirstUse(context.Background(), "jti-2", time.Minute); !first || !again {
		t.Fatalf("a mark expires with its ttl")
	}
}

func TestMemoryFirstUseIsAtomic(t *testing.T) {
	store := NewMemory()
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := store.FirstUse(context.Background(), "same", time.Minute); ok {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one of 50 racing requests is first, got %d", wins)
	}
}
