package safex

import (
	"strings"
	"testing"
)

// TestRedactProperty is a fast property test: for any string, Redact
// must be idempotent and must never leave a scheme://user:pass@host  # secret-scan:allow-line synthetic documentation example of the redacted pattern
// pattern intact.
func TestRedactProperty(t *testing.T) {
	// Deterministic mini-corpus (fast; no infinite runs).
	corpus := []string{
		"",
		"plain text",
		"https://u:p@h.example/x", // secret-scan:allow-line synthetic redaction test vector
		"http://user:pass@host",   // secret-scan:allow-line synthetic redaction test vector
		"password: value123",
		"secret=xzy123abc",
		"Authorization: Bearer abc.def.ghi",
		"nested (https://a:b@c.example) parens",      // secret-scan:allow-line synthetic redaction test vector
		"url at end https://x:y@z.example",           // secret-scan:allow-line synthetic redaction test vector
		strings.Repeat("https://a:b@c.example ", 50), // secret-scan:allow-line synthetic redaction test vector
		"?password=realvalue123",
		"&token=abcdef456",
		";secret=ghijk789",
		"mypassword=value123",
	}
	for _, in := range corpus {
		once := Redact(in)
		twice := Redact(once)
		if once != twice {
			t.Errorf("not idempotent for %q: %q vs %q", in, once, twice)
		}
		if i := strings.Index(once, "://"); i >= 0 {
			rest := once[i+3:]
			if j := strings.IndexAny(rest, " \t\n\"'<)"); j >= 0 {
				rest = rest[:j]
			}
			if k := strings.Index(rest, ":"); k >= 0 && strings.Contains(rest[k:], "@") {
				t.Errorf("userinfo survived redaction in %q -> %q", in, once)
			}
		}
	}
}

// TestRedactFuzzSeed is a seeded, bounded "fuzz-style" loop: random
// mutations of a sensitive corpus are redacted and the invariants
// (idempotence, no userinfo) are asserted. Runs in bounded time.
func TestRedactFuzzSeed(t *testing.T) {
	base := []string{
		"https://alice:secret@proxy.example:8444/path", // secret-scan:allow-line synthetic redaction test vector
		"token: abcdef1234567890ABCDEF",
		"https://user:pass@host", // secret-scan:allow-line synthetic redaction test vector
		"?password=realvalue123",
	}
	// Simple deterministic LCG for reproducibility.
	state := uint32(123456789)
	next := func(n int) int {
		state = state*1664525 + 1013904223
		return int(state>>16) % n
	}
	for i := 0; i < 500; i++ {
		s := base[next(len(base))]
		// random splice
		pos := next(len(s))
		insert := []string{"x", "://", ":", "@", "password=", "\n", "\"", "?", "&", ";"}[next(10)]
		s = s[:pos] + insert + s[pos:]
		once := Redact(s)
		if Redact(once) != once {
			t.Errorf("not idempotent for %q -> %q", s, once)
		}
	}
}

// FuzzRedact asserts one-call idempotence of Redact. The seed corpus
// carries every bounded-fuzz failure input found so far so plain
// `go test` reproduces them; `go test -fuzz=FuzzRedact` continues the
// search.
func FuzzRedact(f *testing.F) {
	for _, s := range []string{
		"https://u:p@h.example", "password: v", "Authorization: Bearer x", // secret-scan:allow-line synthetic redaction test vector
		"", ":", "@", "://",
		// Regression seeds from bounded-fuzz failure corpora:
		// overlapping "://" and "@" markers, re-segmentation of a
		// masked quoted value, and invalid UTF-8 changing byte length
		// under ToLower each previously broke one-call idempotence
		// (or panicked).
		"://@://@",
		"pwd:\"\"0",
		"\xc8 pwd:",
		// Assignment-pass output later matched by the header pass;
		// the ",0" variant additionally exercised unquoted colon
		// values that must extend to end of line for cross-pass
		// agreement.
		"Authorization:0,",
		"Authorization:0,0",
		// Several sensitive keys on one line where a mask changes the
		// line length (stale-lower defect).
		"password: realvalue123 token=abcdef456",
		// Placeholder first, real value of the same key second
		// (first-occurrence-only leak).
		"password=${VAR}, password=realvalue123",
		// Query/log delimiter prefixes before a sensitive key
		// (boundary-detection gap).
		"?password=realvalue123",
		"&token=abcdef456",
		";secret=ghijk789",
		// Identifier-internal keys must NOT be flagged.
		"mypassword=value123",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		once := Redact(s)
		if twice := Redact(once); twice != once {
			t.Errorf("not idempotent: %q -> %q -> %q", s, once, twice)
		}
	})
}
