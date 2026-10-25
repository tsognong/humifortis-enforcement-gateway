package aauth

import (
	"reflect"
	"testing"
)

// Small assertions on the standard library only: the gateway has no test dependency and gains none.

func eq(t *testing.T, want, got any, msg ...any) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("%v\n want: %#v\n  got: %#v", msg, want, got)
	}
}

func isTrue(t *testing.T, cond bool, msg ...any) {
	t.Helper()
	if !cond {
		t.Fatalf("expected true: %v", msg)
	}
}

func isFalse(t *testing.T, cond bool, msg ...any) {
	t.Helper()
	if cond {
		t.Fatalf("expected false: %v", msg)
	}
}

func noErr(t *testing.T, err error, msg ...any) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v %v", err, msg)
	}
}

// noFail fails the test when the verifier returned a refusal.
func noFail(t *testing.T, e *Error, msg ...any) {
	t.Helper()
	if e != nil {
		t.Fatalf("unexpected refusal %s (%s) %v", e.Code, e.Reason, msg)
	}
}

// refused asserts the refusal is the code (and, when given, the reason).
func refused(t *testing.T, e *Error, code Code, reason ...Reason) {
	t.Helper()
	if e == nil {
		t.Fatalf("expected a refusal %s, got none", code)
	}
	if e.Code != code {
		t.Fatalf("expected %s, got %s (%s %s)", code, e.Code, e.Reason, e.Detail)
	}
	if len(reason) > 0 && e.Reason != reason[0] {
		t.Fatalf("expected reason %s, got %s", reason[0], e.Reason)
	}
}
