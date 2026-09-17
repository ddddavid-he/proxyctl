package render

import (
	"net"
	"strconv"
	"strings"
	"unicode/utf8"

	"proxyctl/internal/safex"
)

// quoteYAML renders v as a YAML double-quoted scalar. The YAML 1.2
// double-quoted style escapes only '"' and '\\' plus control/format
// characters; '#', ':' and every other printable character are literal
// inside double quotes, so a quoted scalar can never leak out as
// structure (mapping, comment) however hostile its content.
func quoteYAML(v string) string {
	var b strings.Builder
	b.Grow(len(v) + 8)
	b.WriteByte('"')
	for _, r := range v {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			const hex = "0123456789abcdef"
			switch {
			case r == 0x2028 || r == 0x2029:
				// Unicode line/paragraph separators: escaped as \uNNNN.
				b.WriteString(`\u`)
				b.WriteByte(hex[(r>>12)&0xf])
				b.WriteByte(hex[(r>>8)&0xf])
				b.WriteByte(hex[(r>>4)&0xf])
				b.WriteByte(hex[r&0xf])
			case r < 0x20 || r == 0x7f || r == 0x85:
				// C0/DEL/NEL: escaped in the YAML 1.2 \xNN style.
				b.WriteString(`\x`)
				b.WriteByte(hex[(r>>4)&0xf])
				b.WriteByte(hex[r&0xf])
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// isUnsignedDecimal reports whether v is a non-empty string of ASCII
// digits only (no sign, no whitespace, no 0x/0o/underscores), so a raw
// unquoted emission cannot smuggle YAML structure or non-numbers.
func isUnsignedDecimal(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}

// isValidAddress reports whether v is a syntactically valid network
// address: an IPv4 or IPv6 literal, an IPv4:port or [IPv6]:port pair with
// an in-range port, or a hostname of DNS labels (letters, digits,
// dots, hyphens). Anything else (spaces, quotes, colons in odd places,
// placeholder-shaped text) is rejected.
func isValidAddress(v string) bool {
	if v == "" || len(v) > 253 {
		return false
	}
	if net.ParseIP(v) != nil {
		return true
	}
	if h, p, err := net.SplitHostPort(v); err == nil {
		if !isUnsignedDecimal(p) || !portInRange(p) {
			return false
		}
		return net.ParseIP(strings.Trim(h, "[]")) != nil
	}
	// Any residual ':' is an invalid/malformed host:port form, never a
	// bare hostname; reject rather than fall through to the DNS check.
	if strings.Contains(v, ":") {
		return false
	}
	return isDNSHostname(v)
}

// portInRange reports whether the unsigned-decimal string p denotes a
// TCP/UDP port in 1..65535. The string is digit-only (checked by the
// caller), so ParseUint cannot fail on grammar; the range check is the
// semantic guard.
func portInRange(p string) bool {
	n, err := strconv.ParseUint(p, 10, 32)
	return err == nil && n >= 1 && n <= 65535
}

// isDNSHostname reports whether v is a hostname of DNS labels. An
// all-numeric dotted-quad that failed IPv4 parsing (e.g. "999.1.1.1")
// is a malformed IP literal, never a hostname; reject it here so it
// cannot be emitted raw as an "address".
func isDNSHostname(v string) bool {
	if v == "" || len(v) > 253 {
		return false
	}
	labels := strings.Split(v, ".")
	allNumeric := len(labels) == 4
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		numeric := true
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c != '-' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
				return false
			}
			if c < '0' || c > '9' {
				numeric = false
			}
		}
		allNumeric = allNumeric && numeric
	}
	return !allNumeric
}

// containsPlaceholderFragment reports whether v contains any "${"
// fragment, whether or not a closing "}" follows. A substituted value
// must never carry a placeholder fragment (complete OR dangling) into
// later phases or the output: a complete token could be re-interpreted
// as a nested placeholder, and a dangling fragment is ambiguous
// template syntax. Both are rejected outright.
func containsPlaceholderFragment(v string) bool {
	return strings.Contains(v, "${")
}

// rejectUnsafeValue enforces the insertion contract shared by every
// substituted value: valid UTF-8, no line breaks, no control
// characters, and no placeholder fragment of any kind. The returned
// error is fixed text only — it never echoes the value or any name,
// so attacker-controlled content can never reach a diagnostic.
func rejectUnsafeValue(v string) error {
	if !utf8.ValidString(v) {
		return safex.New(safex.CodeConfigRejected,
			"substitution value is not valid UTF-8")
	}
	if strings.ContainsAny(v, "\r\n") || strings.IndexFunc(v, isYAMLControl) >= 0 {
		return safex.New(safex.CodeConfigRejected,
			"substitution value contains a line break or control character")
	}
	if containsPlaceholderFragment(v) {
		return safex.New(safex.CodeConfigRejected,
			"substitution value contains a placeholder fragment")
	}
	return nil
}

// isYAMLControl reports whether r is a character that must never
// appear literally in a rendered config line: C0 controls, DEL, NEL,
// or the Unicode line/paragraph separators.
func isYAMLControl(r rune) bool {
	return r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029
}

// emit renders one resolved value according to its schema kind.
// kindNumber values are validated (grammar, range and per-name bounds)
// and emitted raw. Addresses are validated and then double-quoted,
// like all string values, so YAML-reserved hostnames cannot change
// scalar type. Error messages are fixed text: they never
// echo the value, and name is used ONLY when it is a schema-declared
// (hardcoded) placeholder — never an attacker-controlled unknown name.
func emit(name string, kind placeholderKind, v string) (string, error) {
	// Every substituted value, every kind, must satisfy the insertion
	// contract first.
	if err := rejectUnsafeValue(v); err != nil {
		return "", err
	}
	switch kind {
	case kindNumber:
		if !isUnsignedDecimal(v) {
			return "", safex.New(safex.CodeConfigRejected,
				"placeholder ${%s} requires an unsigned decimal number", name)
		}
		if b, ok := kindBounds[name]; ok {
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil || n < uint64(b[0]) || n > uint64(b[1]) {
				return "", safex.New(safex.CodeConfigRejected,
					"placeholder ${%s} is outside its allowed range", name)
			}
		}
		return v, nil
	case kindAddress:
		if !isValidAddress(v) {
			return "", safex.New(safex.CodeConfigRejected,
				"placeholder ${%s} requires a valid network address", name)
		}
		return quoteYAML(v), nil
	default:
		return quoteYAML(v), nil
	}
}
