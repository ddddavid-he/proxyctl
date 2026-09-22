package safex

import (
	"strings"
	"testing"
)

// Assignment lines are masked WHOLE under the conservative fail-closed
// policy: the bare mask replaces the entire line (no key names, no
// placeholder values, no JSON structure). These tests assert that
// policy plus one-call idempotence (fixed point).

func assertBareMaskAndIdempotent(t *testing.T, in string) {
	t.Helper()
	got := Redact(in)
	if got != mask {
		t.Errorf("Redact(%q) = %q, want bare %q", in, got, mask)
	}
	if again := Redact(got); again != got {
		t.Errorf("not a fixed point after one call: %q -> %q", got, again)
	}
}

func assertNoLeakAndIdempotent(t *testing.T, in string, leaked ...string) {
	t.Helper()
	got := Redact(in)
	for _, l := range leaked {
		if strings.Contains(got, l) {
			t.Errorf("Redact(%q) leaked %q in %q", in, l, got)
		}
	}
	if again := Redact(got); again != got {
		t.Errorf("not a fixed point after one call: %q -> %q", got, again)
	}
}

func TestRedactURLUserinfo(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://user:secretpw@example.com:8444/path", "https://<REDACTED>@example.com:8444/path"},                                                 // secret-scan:allow-line synthetic redaction test vector
		{"connect to https://alice:hunter2@native-gateway.example:8444 failed", "connect to https://<REDACTED>@native-gateway.example:8444 failed"}, // secret-scan:allow-line synthetic redaction test vector
		{"https://example.com/no-userinfo", "https://example.com/no-userinfo"},
		{"see https://git.example.com/x and https://u:p@git.example.com/y", "see https://git.example.com/x and https://<REDACTED>@git.example.com/y"}, // secret-scan:allow-line synthetic redaction test vector
	}
	for _, c := range cases {
		if got := Redact(c.in); got != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestRedactOverlappingSchemeAtRegression is the explicit regression
// for the bounded-fuzz FuzzRedact failure corpus "://@://@": a single
// left-to-right pass left the input one masking step away from the
// fixed point, so a second Redact call masked again and violated
// idempotence. Redact must now reach the fixed point in ONE call, and
// no unmasked userinfo may remain.
func TestRedactOverlappingSchemeAtRegression(t *testing.T) {
	in := "://@://@" // exact failing corpus string from FuzzRedact
	got := Redact(in)
	if again := Redact(got); again != got {
		t.Errorf("not a fixed point after one call: %q -> %q", got, again)
	}
	// Every "@" in the output must be part of a "<REDACTED>@" mask.
	if strings.Count(got, "@") != strings.Count(got, "<REDACTED>@") {
		t.Errorf("unmasked userinfo remains in %q", got)
	}
}

// TestRedactMaskedQuotedValueRegression is the explicit regression for
// the bounded-fuzz failure corpus `pwd:""0`: after the first masking
// pass the line re-segments (masked value followed by trailing text),
// and a second Redact call used to mask again. Under the whole-line
// policy the line is the bare mask after one call.
func TestRedactMaskedQuotedValueRegression(t *testing.T) {
	assertBareMaskAndIdempotent(t, `pwd:""0`)
}

// TestRedactNonUTF8LineRegression is the explicit regression for the
// bounded-fuzz failure corpus "\xc8 pwd:": strings.ToLower can change
// byte length on invalid UTF-8, which previously invalidated index
// arithmetic and panicked. Such lines now fail closed to the mask.
func TestRedactNonUTF8LineRegression(t *testing.T) {
	assertBareMaskAndIdempotent(t, "\xc8 pwd:")
}

// TestRedactAuthorizationCrossPhaseRegression is the explicit
// regression for the bounded-fuzz corpora "Authorization:0," and
// "Authorization:0,0": the assignment pass previously masked the value
// only, and the header pass re-masked to end of line on a second
// Redact call, breaking idempotence. Whole-line masking resolves this
// in one call.
func TestRedactAuthorizationCrossPhaseRegression(t *testing.T) {
	assertBareMaskAndIdempotent(t, "Authorization:0,")
	assertBareMaskAndIdempotent(t, "Authorization:0,0")
}

// TestRedactMultipleKeysSameLineRegression is the explicit regression
// for the stale-lower defect: when one line contains several different
// sensitive keys and the first mask changed the line LENGTH, the
// remaining keys previously operated on stale lowercase indexes.
// Under the whole-line policy every assignment line is the bare mask.
func TestRedactMultipleKeysSameLineRegression(t *testing.T) {
	assertBareMaskAndIdempotent(t, "password: realvalue123 token=abcdef456")
	assertBareMaskAndIdempotent(t, "token=abcdef456 password: realvalue123")
}

// TestRedactDuplicateSensitiveKeysRegression is the explicit regression
// for the first-occurrence-only defect: a line whose FIRST occurrence
// of a sensitive key was an allowed placeholder previously caused the
// SAME key's later real value to pass through unmasked (actual leak).
// Under the whole-line policy the presence of any sensitive-key
// assignment masks the entire line, placeholders included.
func TestRedactDuplicateSensitiveKeysRegression(t *testing.T) {
	// The exact reported leak boundary: placeholder first, real value
	// second — now the whole line is the bare mask.
	assertBareMaskAndIdempotent(t, "password=${VAR}, password=realvalue123")
	assertBareMaskAndIdempotent(t, "password: ${VAR} password: realvalue123")
	assertBareMaskAndIdempotent(t, "secret=abc123def, token: gh456ijk789")
	assertBareMaskAndIdempotent(t, "auth=a1b2c3d4 auth=e5f6g7h8 auth=i9j0k1l2")
}

// TestRedactAssignmentFormsWholeLine covers the whole-line policy for
// the assignment shapes: eq, colon, quoted JSON key, mixed separator
// spacing and placeholder values (also masked: structure is not
// preserved by design).
func TestRedactAssignmentFormsWholeLine(t *testing.T) {
	assertBareMaskAndIdempotent(t, "password: realvalue123")
	assertBareMaskAndIdempotent(t, "password=${TROJAN_PASSWORD_1}")
	assertBareMaskAndIdempotent(t, `{"secret": "abc123def456"}`)
	assertBareMaskAndIdempotent(t, "token=abcdef123456")
	assertBareMaskAndIdempotent(t, "auth = ${VAR}")
	assertBareMaskAndIdempotent(t, "password: <REDACTED_PW>")
	// Non-assignment lines pass through unchanged.
	for _, keep := range []string{
		"plain text without sensitive keys",
		"the authorization concept discussed",
		"public-port: 7890",
	} {
		if got := Redact(keep); got != keep {
			t.Errorf("Redact(%q) = %q, want unchanged", keep, got)
		}
	}
}

// TestRedactQueryDelimiterPrefixesRegression is the explicit regression
// for the boundary-detection gap: query-string and log delimiters
// ('?', '&', ';') before a sensitive key were previously not
// recognized as identifier boundaries, so `?password=...`,
// `&token=...` and `;secret=...` leaked. Any non-alphanumeric byte
// before the key now counts as a boundary.
func TestRedactQueryDelimiterPrefixesRegression(t *testing.T) {
	assertBareMaskAndIdempotent(t, "?password=realvalue123")
	assertBareMaskAndIdempotent(t, "&token=abcdef456")
	assertBareMaskAndIdempotent(t, ";secret=ghijk789")
	// Leaked values must not survive anywhere in the output.
	assertNoLeakAndIdempotent(t, "GET /x?password=realvalue123 HTTP/1.1", "realvalue123")
}

// TestRedactIdentifierInternalNotFlagged: a sensitive key embedded
// inside a larger identifier must NOT trigger the mask (mypassword=...
// is a different key). Conservative false positives are acceptable
// only at true boundaries.
func TestRedactIdentifierInternalNotFlagged(t *testing.T) {
	for _, keep := range []string{
		"mypassword=value123",
		"xtoken=abc",
	} {
		if got := Redact(keep); got != keep {
			t.Errorf("Redact(%q) = %q, want unchanged (identifier-internal key)", keep, got)
		}
	}
}

func TestRedactHeaderAuth(t *testing.T) {
	// Header credentials mask to end of line; the assignment pass then
	// masks the whole line within the same Redact call.
	in := "header Authorization: Basic dXNlcjpwYXNz failed"
	if got := Redact(in); got != mask {
		t.Errorf("Redact(%q) = %q, want bare %q", in, got, mask)
	}
	in2 := "proxy-authorization: Bearer xyz\nnext line"
	got2 := Redact(in2)
	if got2 != mask+"\nnext line" {
		t.Errorf("Redact(%q) = %q", in2, got2)
	}
}

func TestRedactIdempotent(t *testing.T) {
	in := "https://u:p@h.example and password: secretvalue" // secret-scan:allow-line synthetic redaction test vector
	once := Redact(in)
	twice := Redact(once)
	if once != twice {
		t.Errorf("Redact not idempotent: %q vs %q", once, twice)
	}
}

func TestIsPlaceholder(t *testing.T) {
	yes := []string{"${VAR}", "$PASSWORD_1", "<REDACTED_X>", "<domain>", ""}
	no := []string{"realpassword", "user:pass", "${lower}", "abc"}
	for _, v := range yes {
		if !IsPlaceholder(v) {
			t.Errorf("IsPlaceholder(%q) = false, want true", v)
		}
	}
	for _, v := range no {
		if IsPlaceholder(v) {
			t.Errorf("IsPlaceholder(%q) = true, want false", v)
		}
	}
}

func TestExitCodesStable(t *testing.T) {
	cases := map[Code]int{
		CodeOK: 0, CodeUsage: 2, CodeUnknownCommand: 3, CodeUnknownFlag: 4,
		CodeInvalidEnum: 5, CodeNotFound: 6, CodePermission: 7,
		CodeConfigRejected: 8, RenderUnsafe: 8, CodeIO: 9, CodeInternal: 10,
	}
	for c, want := range cases {
		if got := c.ExitCode(); got != want {
			t.Errorf("Code(%s).ExitCode() = %d, want %d", c, got, want)
		}
	}
}

func TestErrorRedactedAtConstruction(t *testing.T) {
	// The message is redacted at construction; under the whole-line
	// policy an embedded sensitive assignment collapses the line to
	// the bare mask (structure is sacrificed, never leaked).
	e := New(CodeConfigRejected, "reject %s", "password: supersecret1")
	if e.Message != mask {
		t.Errorf("e.Message = %q, want bare %q", e.Message, mask)
	}
	// Non-assignment text is preserved.
	e2 := New(CodeConfigRejected, "reject role %s", "eu")
	if e2.Message != "reject role eu" {
		t.Errorf("e2.Message = %q", e2.Message)
	}
	if got := ExitError(e); got != 8 {
		t.Errorf("ExitError = %d, want 8", got)
	}
}
