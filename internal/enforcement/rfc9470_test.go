package enforcement

import (
	"strings"
	"testing"
)

func TestChallengeHeader_SpeaksRFC9470(t *testing.T) {
	h := ChallengeHeader("2", 0)
	for _, want := range []string{`Bearer `, `error="insufficient_user_authentication"`, `acr_values="urn:humifortis:acr:app"`} {
		if !strings.Contains(h, want) {
			t.Errorf("%q must contain %q", h, want)
		}
	}
	if strings.Contains(h, "max_age") {
		t.Error("no max_age asked: none sent")
	}
}

func TestChallengeHeader_LevelsAndGenericMFA(t *testing.T) {
	cases := map[string]string{
		"1": "urn:humifortis:acr:code", "2": "urn:humifortis:acr:app", "3": "urn:humifortis:acr:key",
		"9": "urn:humifortis:acr:key", "MFA": "urn:humifortis:acr:code", "": "urn:humifortis:acr:code",
	}
	for in, acr := range cases {
		if h := ChallengeHeader(in, 0); !strings.Contains(h, `acr_values="`+acr+`"`) {
			t.Errorf("required %q: %q does not ask for %s", in, h, acr)
		}
	}
}

func TestChallengeHeader_MaxAgeIsAFreshSignIn(t *testing.T) {
	if h := ChallengeHeader("1", 300); !strings.HasSuffix(h, ", max_age=300") {
		t.Errorf("max_age missing: %q", h)
	}
}
