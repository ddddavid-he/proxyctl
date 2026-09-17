// Package config loads and validates proxy configuration documents.
//
// A config document is a YAML mapping of ${VAR} placeholders (the forms
// committed to Git). Validation is strictly allow-list based: any
// unknown top-level field, any unknown listener/proxy field, any
// non-placeholder credential value, and any unsafe network posture
// (DIRECT fallback, insecure TLS, public 7890, 0.0.0.0 controller,
// empty credentials) is rejected before rendering.
//
// Only the standard library is used; the parser is intentionally
// minimal and strict (flat mappings of scalars per section item).
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"proxyctl/internal/safex"
)

// Role identifies a host role in the two-tier topology.
type Role string

const (
	RoleGateway Role = "gateway"
	RoleEgress  Role = "egress"
)

// ParseRole validates a role string.
func ParseRole(s string) (Role, error) {
	switch Role(s) {
	case RoleGateway:
		return RoleGateway, nil
	case RoleEgress:
		return RoleEgress, nil
	}
	return "", safex.New(safex.CodeInvalidEnum, "invalid role %q: must be gateway or egress", s)
}

// Profile identifies a verification profile.
type Profile string

const (
	ProfileLoopback Profile = "loopback"
	ProfileCanary   Profile = "canary"
)

// ParseProfile validates a profile string.
func ParseProfile(s string) (Profile, error) {
	switch Profile(s) {
	case ProfileLoopback:
		return ProfileLoopback, nil
	case ProfileCanary:
		return ProfileCanary, nil
	}
	return "", safex.New(safex.CodeInvalidEnum, "invalid profile %q: must be loopback or canary", s)
}

var placeholderRe = regexp.MustCompile(`^\$\{[A-Z][A-Z0-9_]*\}$`)

// isPlaceholder reports whether v is exactly a ${VAR} placeholder.
func isPlaceholder(v string) bool { return placeholderRe.MatchString(v) }

// scalarLine is one `key: value` pair at zero indentation.
type scalarLine struct {
	key   string
	value string
}

// itemLine is one `- key: value` pair inside a list (item start).
type itemLine struct {
	key   string
	value string
}

// Document is the parsed, ordered representation of a config file. It
// preserves structure enough to validate allow-lists and re-render.
type Document struct {
	Role    Role
	scalars map[string]string
	// sections maps section name -> ordered items; each item is an
	// ordered list of key/value pairs.
	sections map[string][][2]string
	// unknown tracks the first unknown field for error reporting.
	rawLines []string
}

// ParseFile reads and validates a config file for the given role.
// The final path component is Lstat'ed first: symlinks and directories
// are refused, so a caller-supplied config path can never read through
// a symlink escape.
func ParseFile(path string, role Role) (*Document, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, safex.New(safex.CodeIO, "cannot stat config file").Wrap(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, safex.New(safex.CodeConfigRejected, "config path is a symlink; refusing to read")
	}
	if fi.IsDir() {
		return nil, safex.New(safex.CodeConfigRejected, "config path is a directory, not a file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, safex.New(safex.CodeIO, "cannot read config file").Wrap(err)
	}
	return Parse(string(data), role)
}

// Parse validates a config document (YAML subset: top-level scalars and
// one level of lists of scalars) against the role's allow-list.
func Parse(text string, role Role) (*Document, error) {
	doc := &Document{
		Role:     role,
		scalars:  map[string]string{},
		sections: map[string][][2]string{},
	}
	lines := strings.Split(text, "\n")
	var curSection string
	var curItemIdx = -1
	for ln, raw := range lines {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		doc.rawLines = append(doc.rawLines, trimmed)
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			pair := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			k, v, ok := splitKV(pair)
			if !ok {
				return nil, safex.New(safex.CodeConfigRejected,
					"config line %d: malformed list item", ln+1)
			}
			if curSection == "" {
				return nil, safex.New(safex.CodeConfigRejected,
					"config line %d: list item outside a section", ln+1)
			}
			doc.sections[curSection] = append(doc.sections[curSection], [2]string{k, v})
			curItemIdx++
			continue
		}
		k, v, ok := splitKV(trimmed)
		if !ok {
			return nil, safex.New(safex.CodeConfigRejected,
				"config line %d: expected 'key: value'", ln+1)
		}
		if indent == 0 {
			if v == "" && isSectionName(role, k) {
				// A valueless top-level key opens a known section
				// (e.g. "listeners:" or "users:").
				curSection = k
				curItemIdx = -1
				continue
			}
			if v == "" {
				return nil, safex.New(safex.CodeConfigRejected,
					"config line %d: field %q has an empty value", ln+1, k)
			}
			curSection = ""
			curItemIdx = -1
			doc.scalars[k] = v
			continue
		}
		// indented key inside a section item
		if curSection == "" {
			return nil, safex.New(safex.CodeConfigRejected,
				"config line %d: indented field without an item", ln+1)
		}
		doc.sections[curSection] = append(doc.sections[curSection], [2]string{k, v})
	}

	if err := doc.validate(role); err != nil {
		return nil, err
	}
	return doc, nil
}

func splitKV(s string) (string, string, bool) {
	i := strings.Index(s, ":")
	if i <= 0 {
		return "", "", false
	}
	k := strings.TrimSpace(s[:i])
	v := strings.TrimSpace(s[i+1:])
	if k == "" {
		return "", "", false
	}
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	return k, v, true
}

// roleAllowlists defines the accepted top-level scalar keys per role.
var roleAllowlists = map[Role]map[string]bool{
	RoleGateway: {
		"schema": true, "role": true, "mixed-port": true,
		"bind-address": true, "controller-listen": true,
		"gateway-egress-password": true, "gateway-egress-user": true,
		"egress-server": true, "egress-port": true, "egress-sni": true,
	},
	RoleEgress: {
		"schema": true, "role": true, "listen-address": true,
		"port": true, "sni": true, "gateway-node-user": true,
		"gateway-node-password": true, "max-users": true,
	},
}

// sectionAllowlists defines accepted section names and their item keys.
var sectionAllowlists = map[Role]map[string][]string{
	RoleGateway: {
		"listeners": {"name", "type", "listen", "port", "users"},
		"users":     {"username", "password"},
	},
	RoleEgress: {
		"users": {"username", "password"},
	},
}

// isSectionName reports whether k is a known section for the role.
func isSectionName(role Role, k string) bool {
	_, ok := sectionAllowlists[role][k]
	return ok
}

func (d *Document) validate(role Role) error {
	scalarOK, ok := roleAllowlists[role]
	if !ok {
		return safex.New(safex.CodeInternal, "no allowlist for role %s", role)
	}
	for k := range d.scalars {
		if !scalarOK[k] {
			return safex.New(safex.CodeConfigRejected,
				"unknown field %q for role %s (not in allowlist)", k, role)
		}
	}
	sectionsOK := sectionAllowlists[role]
	for name, items := range d.sections {
		allowed, ok := sectionsOK[name]
		if !ok {
			return safex.New(safex.CodeConfigRejected,
				"unknown section %q for role %s (not in allowlist)", name, role)
		}
		for _, kv := range items {
			if !contains(allowed, kv[0]) {
				return safex.New(safex.CodeConfigRejected,
					"unknown field %q in section %q (not in allowlist)", kv[0], name)
			}
		}
	}

	// schema/role binding
	if d.scalars["schema"] != "private-proxy/v1" {
		return safex.New(safex.CodeConfigRejected,
			"unsupported schema %q: only private-proxy/v1 is accepted", d.scalars["schema"])
	}
	if d.scalars["role"] != string(role) {
		return safex.New(safex.CodeConfigRejected,
			"config role %q does not match requested role %s", d.scalars["role"], role)
	}

	// credential placeholders must be placeholders (no real secrets in Git)
	credFields := []string{"gateway-egress-password", "gateway-node-password"}
	for _, f := range credFields {
		if v, ok := d.scalars[f]; ok && !isPlaceholder(v) {
			return safex.New(safex.CodeConfigRejected,
				"field %q must be a ${VAR} placeholder, real secrets are rejected", f)
		}
	}
	for name, items := range d.sections {
		if name != "users" {
			continue
		}
		for _, kv := range items {
			if kv[0] == "password" && !isPlaceholder(kv[1]) {
				return safex.New(safex.CodeConfigRejected,
					"user password in section %q must be a ${VAR} placeholder", name)
			}
		}
	}
	return d.validateNetworkPosture(role)
}

// validateNetworkPosture enforces the fail-closed security matrix.
func (d *Document) validateNetworkPosture(role Role) error {
	if role == RoleGateway {
		if port := d.scalars["egress-port"]; port != "" && port != "443" {
			return safex.New(safex.CodeConfigRejected, "gateway upstream port must be fixed to UDP 443")
		}
	}
	if role == RoleEgress {
		if user := d.scalars["gateway-node-user"]; !isMachineUser(user) {
			return safex.New(safex.CodeConfigRejected, "egress client user is invalid")
		}
		if port := d.scalars["port"]; port != "" && port != "443" {
			return safex.New(safex.CodeConfigRejected, "egress listener port must be fixed to UDP 443")
		}
	}
	for k, v := range d.scalars {
		switch k {
		case "mixed-port":
			if v == "7890" || v == `"7890"` {
				if addr := d.scalars["bind-address"]; addr != "127.0.0.1" {
					return safex.New(safex.CodeConfigRejected,
						"mixed-port 7890 must bind 127.0.0.1, got %q", addr)
				}
			}
		case "controller-listen":
			host := v
			// strip :port (IPv4) or [v6]:port forms
			if i := strings.LastIndex(v, ":"); i >= 0 {
				host = strings.TrimSuffix(v[:i], "]")
				host = strings.TrimPrefix(host, "[")
			}
			if host == "0.0.0.0" || host == "::" || host == "" && strings.HasPrefix(v, ":") {
				return safex.New(safex.CodeConfigRejected,
					"controller must not listen on all interfaces (%q)", v)
			}
		case "gateway-egress-password", "gateway-node-password":
			if v == "" {
				return safex.New(safex.CodeConfigRejected, "empty credential %q", k)
			}
		}
	}
	if strings.Contains(strings.Join(d.rawLines, "\n"), "DIRECT") {
		return safex.New(safex.CodeConfigRejected,
			"DIRECT fallback is forbidden (fail-closed policy)")
	}
	for _, banned := range []string{"skip-cert-verify: true", "insecure: true"} {
		if strings.Contains(strings.Join(d.rawLines, "\n"), banned) {
			return safex.New(safex.CodeConfigRejected,
				"insecure TLS option forbidden: %s", banned)
		}
	}
	// listener posture (gateway only has listeners)
	for _, kv := range d.sections["listeners"] {
		if kv[0] == "listen" && (kv[1] == "0.0.0.0" && portOfListener(d.sections["listeners"], kv) == "7890") {
			return safex.New(safex.CodeConfigRejected,
				"listener on 0.0.0.0:7890 is forbidden (public mixed-port)")
		}
	}
	// empty users
	for name, items := range d.sections {
		if name != "users" {
			continue
		}
		usernames := 0
		for _, kv := range items {
			if kv[0] == "username" {
				usernames++
				if kv[1] == "" {
					return safex.New(safex.CodeConfigRejected, "empty username in users section")
				}
			}
		}
		if usernames == 0 && items != nil {
			return safex.New(safex.CodeConfigRejected, "users section has no username entries")
		}
	}
	return nil
}

func isMachineUser(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !('a' <= r && r <= 'z') && !('A' <= r && r <= 'Z') &&
			!('0' <= r && r <= '9') && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func portOfListener(items [][2]string, kv [2]string) string {
	// find the port after this listen key in the same item
	found := false
	for _, it := range items {
		if found && it[0] == "port" {
			return it[1]
		}
		if it == kv {
			found = true
			continue
		}
		if it[0] == "name" {
			found = false
		}
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Scalar returns a top-level scalar value from the document.
func (d *Document) Scalar(key string) (string, bool) {
	v, ok := d.scalars[key]
	return v, ok
}

// SectionItems returns the ordered key/value pairs of a section.
func (d *Document) SectionItems(name string) [][2]string {
	return d.sections[name]
}

// Users returns the usernames declared in the users section.
func (d *Document) Users() []string {
	var out []string
	for _, kv := range d.sections["users"] {
		if kv[0] == "username" {
			out = append(out, kv[1])
		}
	}
	return out
}

// Summary returns a redacted one-line summary safe for status output.
func (d *Document) Summary() string {
	return fmt.Sprintf("role=%s schema=%s users=%d", d.Role, d.scalars["schema"], len(d.Users()))
}
