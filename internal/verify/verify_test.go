package verify

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProfiles(t *testing.T) {
	for _, p := range []string{"loopback", "canary"} {
		res, err := Run(Options{Profile: p})
		if err != nil {
			t.Fatalf("profile %s failed: %v", p, err)
		}
		if !res.OK {
			t.Errorf("profile %s not OK", p)
		}
		b, _ := json.Marshal(res)
		s := string(b)
		for _, banned := range []string{"password", "Authorization", "token", "https://"} {
			if strings.Contains(s, banned) {
				t.Errorf("profile %s output contains banned token %q", p, banned)
			}
		}
	}
}

func TestInvalidProfileRejected(t *testing.T) {
	if _, err := Run(Options{Profile: "full"}); err == nil {
		t.Fatal("invalid profile accepted")
	}
}

func TestCanaryRedaction(t *testing.T) {
	res, _ := Run(Options{Profile: "canary"})
	// Canary must include the no-secret-in-report invariant.
	found := false
	for _, c := range res.Checks {
		if c.Name == "no-secret-in-report" {
			found = true
		}
	}
	if !found {
		t.Error("canary profile missing no-secret-in-report check")
	}
}

func TestRedactTargetURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://user:pw@native-gateway.example:8444/path?x=1", "https://native-gateway.example:8444"},
		{"https://plain.example/a/b/c", "https://plain.example"},
		{"notaurl", "<redacted>"},
	}
	for _, c := range cases {
		if got := RedactTargetURL(c.in); got != c.want {
			t.Errorf("RedactTargetURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
