package aauth

import "testing"

func TestSFV_Dictionary(t *testing.T) {
	m, err := parseDictionary(`sig=("@method" "@authority");created=1618884473;keyid="k", other=:aGk=:, flag`)
	noErr(t, err)
	eq(t, 3, len(m))
	isTrue(t, m[0].inner && len(m[0].items) == 2, "inner list")
	eq(t, `("@method" "@authority");created=1618884473;keyid="k"`, m[0].raw, "the raw text is kept for the signature base")
	v, ok := findParam(m[0].params, "created")
	isTrue(t, ok && v.num == 1618884473)
	eq(t, "hi", string(m[1].item.raw))
	isTrue(t, m[2].item.kind == kindBoolean && m[2].item.b, "a bare key is true")
}

func TestSFV_Rejects(t *testing.T) {
	for _, s := range []string{
		`sig=("a"`, `sig=`, `Sig=1`, `sig=1,,x=2`, `sig=1,`, `sig="unterminated`, `sig=:!!!:`, `sig=99999999999999999999`,
		`sig=("a" "b";)`, `sig=?2`, "sig=\"a\x01\"", `sig=1;A=2`, `=1`,
	} {
		if _, err := parseDictionary(s); err == nil {
			t.Fatalf("%q must not parse", s)
		}
	}
}

func TestSFV_DuplicateKeysAreRefused(t *testing.T) {
	if _, err := parseDictionary(`a=1, a=2`); err == nil {
		t.Fatal("a duplicate key must be refused")
	}
}

func TestSFV_CombineField(t *testing.T) {
	eq(t, "a, b", combineField([]string{" a ", "b"}))
	eq(t, "", combineField(nil))
}
