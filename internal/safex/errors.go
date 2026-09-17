// Package safex provides centralized redaction and stable error
// classification for proxyctl. It is the only package that decides how
// errors and user-facing strings are sanitized: passwords, auth headers,
// bearer tokens, URL userinfo and full target URLs must never reach
// command output or generated reports.
package safex

import (
	"fmt"
	"strings"
)

// Code is a stable, machine-readable error category. Codes are part of
// the CLI contract: they must never be renamed or reused for a different
// meaning within a major version.
type Code string

const (
	CodeOK               Code = "OK"
	CodeUsage            Code = "USAGE"
	CodeUnknownCommand   Code = "UNKNOWN_COMMAND"
	CodeUnknownFlag      Code = "UNKNOWN_FLAG"
	CodeInvalidEnum      Code = "INVALID_ENUM"
	CodeNotFound         Code = "NOT_FOUND"
	CodePermission       Code = "PERMISSION"
	CodeConfigRejected   Code = "CONFIG_REJECTED"
	CodeTemplateRejected Code = "TEMPLATE_REJECTED"
	RenderUnsafe         Code = "RENDER_UNSAFE"
	CodeIO               Code = "IO"
	CodeInternal         Code = "INTERNAL"
)

// ExitCode maps a Code to a stable process exit code.
func (c Code) ExitCode() int {
	switch c {
	case CodeOK:
		return 0
	case CodeUsage:
		return 2
	case CodeUnknownCommand:
		return 3
	case CodeUnknownFlag:
		return 4
	case CodeInvalidEnum:
		return 5
	case CodeNotFound:
		return 6
	case CodePermission:
		return 7
	case CodeConfigRejected, CodeTemplateRejected, RenderUnsafe:
		return 8
	case CodeIO:
		return 9
	case CodeInternal:
		return 10
	}
	return 10
}

// Error is the single error type surfaced by proxyctl internals. The
// Message field is pre-redacted and safe for any output; details that
// could carry secrets stay in err (never printed).
type Error struct {
	Code    Code
	Message string
	err     error
}

func (e *Error) Error() string { return e.Message }

// Unwrap returns the wrapped cause (for errors.Is/As use internally;
// callers must not print it).
func (e *Error) Unwrap() error { return e.err }

// New builds a redacted, stable error.
func New(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: Redact(fmt.Sprintf(format, args...))}
}

// Wrap attaches a cause. The cause is never rendered.
func (e *Error) Wrap(err error) *Error {
	e.err = err
	return e
}

// ExitError returns the process exit code for err: 0 for nil, the mapped
// code for *Error, and INTERNAL for anything else (defensive: unknown
// error types are treated as internal and never printed verbatim).
func ExitError(err error) int {
	if err == nil {
		return 0
	}
	var se *Error
	if ok := asError(err, &se); ok {
		return se.Code.ExitCode()
	}
	return CodeInternal.ExitCode()
}

func asError(err error, target **Error) bool {
	for err != nil {
		if e, ok := err.(*Error); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// Redact sanitizes free-form text before it reaches output. It masks:
//   - URL userinfo (scheme://user:password@host -> scheme://<REDACTED>@host)  # secret-scan:allow-line synthetic documentation example of the redacted pattern
//   - key=value / key: value pairs for credential-like keys
//   - Authorization / Proxy-Authorization header values
//
// It is deliberately conservative: when in doubt it masks rather than
// leaks. Redact is idempotent.
func Redact(s string) string {
	if s == "" {
		return s
	}
	s = redactURLCreds(s)
	s = redactHeaderAuth(s)
	s = redactAssignments(s)
	return s
}

// sensitiveKeys are assignment keys whose values are always masked.
var sensitiveKeys = []string{
	"password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
	"auth", "authorization", "proxy-authorization", "private-key",
	"private_key", "client_key", "clientkey", "credential", "credentials",
}

const mask = "<REDACTED>"

// redactURLCreds masks userinfo in URLs appearing anywhere in the text
// (scheme://user:password@host -> scheme://<REDACTED>@host).  # secret-scan:allow-line synthetic documentation example of the redacted pattern
//
// A single left-to-right pass can leave overlapping "://" / "@" inputs
// (e.g. "://@://@") one masking step away from the fixed point, because
// masking changes how a re-parse segments the text. This wrapper
// therefore iterates the pass to a fixed point with an explicit finite
// upper bound: at most (number of "://" occurrences + 1) iterations.
// The bound holds because each changing iteration fully masks at least
// one not-yet-masked authority, masked regions are reproduced verbatim
// on re-parse (the mask starts with '<', an authority terminator, and
// contains no "://" or '@'), and masking never increases the "://"
// count. If the bound is somehow exceeded anyway, the function fails
// closed by returning the bare mask.
func redactURLCreds(s string) string {
	bound := strings.Count(s, "://") + 1
	for n := 0; n < bound; n++ {
		next := redactURLCredsOnce(s)
		if next == s {
			return s
		}
		s = next
	}
	return mask
}

// redactURLCredsOnce is a single left-to-right masking pass.
func redactURLCredsOnce(s string) string {
	var b strings.Builder
	i := 0
	for {
		rel := strings.Index(s[i:], "://")
		if rel < 0 {
			b.WriteString(s[i:])
			return b.String()
		}
		j := i + rel
		authStart := j + 3
		// Authority ends at path, query, fragment, whitespace, or a
		// delimiter that cannot appear in a host.
		authEnd := len(s)
		for k := authStart; k < len(s); k++ {
			c := s[k]
			if c == '/' || c == '?' || c == '#' || c == ' ' || c == '\t' ||
				c == '\n' || c == '\r' || c == '"' || c == '\'' ||
				c == '<' || c == '>' || c == ')' {
				authEnd = k
				break
			}
		}
		authority := s[authStart:authEnd]
		b.WriteString(s[i:authStart])
		if at := strings.LastIndex(authority, "@"); at >= 0 {
			b.WriteString(mask)
			b.WriteString("@")
			b.WriteString(authority[at+1:])
		} else {
			b.WriteString(authority)
		}
		i = authEnd
	}
}

// redactHeaderAuth masks Authorization header values. Header
// credentials mask to end of line (fail closed). This is safe with
// respect to idempotence because any line still containing an
// Authorization assignment afterwards is fully masked by the
// assignment pass in the same Redact call, and the bare mask contains
// no header prefix to re-match.
func redactHeaderAuth(s string) string {
	prefixes := []string{
		"Authorization: ", "authorization: ",
		"Proxy-Authorization: ", "proxy-authorization: ",
	}
	var b strings.Builder
	i := 0
	for i < len(s) {
		// Find the earliest header prefix at or after i.
		best := -1
		bestLen := 0
		for _, p := range prefixes {
			if j := strings.Index(s[i:], p); j >= 0 && (best < 0 || i+j < best) {
				best = i + j
				bestLen = len(p)
			}
		}
		if best < 0 {
			b.WriteString(s[i:])
			break
		}
		b.WriteString(s[i : best+bestLen])
		rest := s[best+bestLen:]
		// Mask to end of line: header credentials are security-critical
		// and trailing same-line tokens are not worth the leak risk.
		end := len(rest)
		for k := 0; k < len(rest); k++ {
			if rest[k] == '\n' || rest[k] == '\r' {
				end = k
				break
			}
		}
		b.WriteString(mask)
		i = best + bestLen + end
	}
	return b.String()
}

// redactAssignments enforces the conservative fail-closed assignment
// policy: any line containing a boundary-valid sensitive-key assignment
// (see hasSensitiveAssignment) is replaced by the bare mask, and any
// line whose lowercase form cannot be byte-aligned (invalid UTF-8 or
// ToLower length change) is masked as well. Placeholder values are NOT
// preserved on assignment lines: structure and key names are
// deliberately sacrificed to keep the rule trivially leak-proof and
// idempotent (the masked line contains no assignment, so re-masking is
// a no-op).
func redactAssignments(s string) string {
	lines := strings.Split(s, "\n")
	for idx, line := range lines {
		lines[idx] = redactLineAssignments(line)
	}
	return strings.Join(lines, "\n")
}

// redactLineAssignments returns the bare mask when the line contains a
// boundary-valid sensitive-key assignment (or cannot be safely
// analyzed), and the line unchanged otherwise.
func redactLineAssignments(line string) string {
	lower := strings.ToLower(line)
	if len(lower) != len(line) {
		// strings.ToLower can change the byte length of non-UTF-8 or
		// special-cased input, which would invalidate the index
		// arithmetic used to map matches back into the original line.
		// Fail closed.
		return mask
	}
	if hasSensitiveAssignment(lower) {
		return mask
	}
	return line
}

// hasSensitiveAssignment reports whether the (lowercased) line contains
// a boundary-valid sensitive-key assignment: the key is preceded by the
// line start or any non-identifier byte (covers '?', '&', ';', quotes,
// whitespace and every other query/log delimiter), optionally followed
// by a closing quote and whitespace, and then a ':' or '=' separator.
// The value itself is irrelevant — its presence alone triggers the
// whole-line mask. A conservative false positive (e.g. a word ending
// in a key) is accepted.
func hasSensitiveAssignment(lower string) bool {
	for _, key := range sensitiveKeys {
		for from := 0; ; {
			rel := findKeyStart(lower[from:], key)
			if rel < 0 {
				break
			}
			start := from + rel
			after := lower[start+len(key):]
			// Allow one closing quote (JSON style "key": value) and
			// optional whitespace before the separator.
			if len(after) > 0 && (after[0] == '"' || after[0] == '\'') {
				after = after[1:]
			}
			after = strings.TrimLeft(after, " \t")
			if strings.HasPrefix(after, ":") || strings.HasPrefix(after, "=") {
				return true
			}
			from = start + len(key)
		}
	}
	return false
}

// findKeyStart finds the start index of key k in the lowercased line,
// requiring an identifier boundary before the key (line start, or the
// preceding byte is not an ASCII alphanumeric character), or -1.
func findKeyStart(lower, k string) int {
	searchFrom := 0
	for {
		idx := strings.Index(lower[searchFrom:], k)
		if idx < 0 {
			return -1
		}
		start := searchFrom + idx
		if start == 0 || !isASCIIAlnum(lower[start-1]) {
			return start
		}
		searchFrom = start + 1
	}
}

// isASCIIAlnum reports whether c is an ASCII alphanumeric byte.
func isASCIIAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// IsPlaceholder reports whether v is a documented placeholder form
// (${VAR}, $VAR, <REDACTED_*>, <...>) that is safe to display.
func IsPlaceholder(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return true
	}
	if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
		inner := v[2 : len(v)-1]
		if inner != "" && isUpperIdent(inner) {
			return true
		}
	}
	if strings.HasPrefix(v, "$") && isUpperIdent(v[1:]) {
		return true
	}
	if strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">") && len(v) > 2 {
		return true
	}
	return false
}

func isUpperIdent(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return len(s) > 0
}
