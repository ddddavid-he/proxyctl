// substitute.go: two-phase, schema-driven template substitution.
//
// Rendering happens in two pure, in-memory phases (no filesystem, no
// environment, no network anywhere in this file):
//
//  1. config phase (substituteConfig): the caller-controlled config
//     document may supply the declared non-secret fields (numbers and
//     validated, quoted network addresses). Credential placeholders may NOT be
//     resolved here; a fixed set of credential placeholder names passes
//     through untouched for phase 2. Everything the config supplies
//     that lands in YAML output is emitted as a YAML double-quoted
//     scalar, so config text can never inject YAML structure.
//  2. bundle phase (substituteCredentials): the fixed credential
//     placeholders resolve from a loaded credential bundle via the
//     narrow BundleSource boundary. Every secret value is validated
//     (single line, no control characters, never placeholder-shaped)
//     and emitted as a YAML double-quoted scalar with quote/backslash
//     escaping, so secret bytes can never break or restructure the
//     output document.
//
// Placeholders are an explicit typed schema (placeholderSchema): only
// names declared there can ever appear in a template. Scalar emission
// is typed: kindString/kindSecret/kindAddress always double-quoted;
// only kindNumber values matching the strict unsigned-decimal grammar
// are emitted raw (unquoted).
//
// Every error message is fixed: errors never echo placeholder values,
// secret bytes or canaries — at most a hardcoded placeholder NAME.
package render

import (
	"strings"

	"proxyctl/internal/config"
	"proxyctl/internal/safex"
)

// substituteConfig performs the config phase: placeholders declared in
// the schema with a NON-secret kind resolve from the config document;
// the fixed credential placeholders (kindSecret) pass through untouched
// for the bundle phase. Every schema placeholder in the template must
// resolve to a config value or be a credential placeholder; unknown
// names were already rejected by validateTemplate, and a declared
// non-secret name with no config value fails before any output.
func substituteConfig(tmpl string, doc *config.Document) (string, error) {
	vals := placeholderValues(doc)
	out := tmpl
	for _, name := range templateVars(tmpl) {
		kind, declared := placeholderSchema[name]
		if !declared {
			// name is attacker-controlled template text here; report a
			// fixed message only, never the name.
			return "", safex.New(safex.CodeTemplateRejected,
				"template references an unknown placeholder (not in schema)")
		}
		if kind == kindSecret {
			continue // credential placeholder: bundle phase resolves it
		}
		v, ok := vals[name]
		if !ok {
			// name is schema-declared (hardcoded), safe to report.
			return "", safex.New(safex.CodeConfigRejected,
				"template placeholder ${%s} has no config value", name)
		}
		e, err := emit(name, kind, v)
		if err != nil {
			return "", err
		}
		out = strings.ReplaceAll(out, "${"+name+"}", e)
	}
	return out, nil
}

// substituteCredentials replaces the fixed credential ${VAR}
// placeholders with bundle scalar values. Unlike the config phase
// (which can only replace values the caller-controlled config file
// provided), this phase injects real secret material, so it is
// maximally strict:
//
//   - every ${VAR} still present must be a schema-declared credential
//     placeholder and must resolve via the bundle's fixed allowlist;
//     unknown names fail closed with a fixed diagnostic;
//   - every credential value must be valid UTF-8, single-line, free of
//     control characters and free of ANY "${" placeholder fragment
//     (complete or dangling), so no nested or ambiguous placeholder can
//     be smuggled through a secret into the output;
//   - every value is emitted as a YAML double-quoted scalar, so secret
//     bytes can never inject YAML structure;
//   - after substitution, ANY remaining ${...} (or a dangling "${"
//     without a closing brace) fails the render BEFORE anything is
//     written, so no placeholder-shaped text can reach an output file.
//
// The returned string is the only artifact; assets stay opaque and are
// handled separately via Materialize.
func substituteCredentials(tmpl string, src BundleSource, documents ...*config.Document) (string, error) {
	out := tmpl
	for _, name := range templateVars(tmpl) {
		kind, declared := placeholderSchema[name]
		if !declared {
			// name is attacker-controlled template text; report a fixed
			// message only, never the name.
			return "", safex.New(safex.CodeTemplateRejected,
				"template references an unknown placeholder (not in schema)")
		}
		if kind != kindSecret {
			// Unreachable after substituteConfig (non-secret names are
			// fully resolved there); fixed post-condition against a
			// future refactor skipping the config phase. name is
			// schema-declared (hardcoded), safe to report.
			return "", safex.New(safex.CodeInternal,
				"non-credential placeholder ${%s} survived to the credential phase", name)
		}
		var v string
		var ok bool
		if name == "GATEWAY_EGRESS_AUTH" {
			if len(documents) != 1 || documents[0] == nil {
				return "", safex.New(safex.CodeInternal,
					"derived credential context is unavailable")
			}
			user, userOK := documents[0].Scalar("gateway-egress-user")
			password, passwordOK := src.Scalar("GATEWAY_EGRESS_PASSWORD_1")
			if userOK && !isHysteriaUser(user) {
				return "", safex.New(safex.CodeConfigRejected,
					"gateway upstream user is invalid")
			}
			if userOK && passwordOK {
				v, ok = user+":"+password, true
			}
		} else {
			v, ok = src.Scalar(name)
		}
		if !ok {
			// name is schema-declared (hardcoded), safe to report.
			return "", safex.New(safex.CodeNotFound,
				"required credential ${%s} is not available", name)
		}
		// An EMPTY credential is refused here as well as in the loader.
		// Defense in depth: a bundle that resolved a placeholder to ""
		// would otherwise publish an empty password/username — a
		// silently unauthenticated config — instead of failing closed.
		if v == "" {
			return "", safex.New(safex.CodeConfigRejected,
				"required credential ${%s} is empty", name)
		}
		// rejectUnsafeValue returns fixed text (no name, no value), so
		// secret bytes can never surface in a diagnostic.
		if err := rejectUnsafeValue(v); err != nil {
			return "", err
		}
		out = replaceAllChecked(out, "${"+name+"}", quoteYAML(v))
	}
	if rest := templateVars(out); len(rest) > 0 {
		// Unreachable given the loop above (each extracted name is
		// either resolved or returned as an error); kept as a fixed
		// post-condition so a future refactor cannot silently ship an
		// unresolved placeholder. rest[0] is schema-declared (anything
		// else returned above), safe to report.
		return "", safex.New(safex.CodeConfigRejected,
			"template placeholder ${%s} has no value after substitution", rest[0])
	}
	if containsDanglingPlaceholder(out) {
		return "", safex.New(safex.CodeTemplateRejected,
			"template contains an unterminated placeholder")
	}
	return out, nil
}

func isHysteriaUser(value string) bool {
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

// NOTE: there is deliberately NO sentinel/stub bundle in production
// code. Run resolves the credential phase exclusively from a bundle
// obtained through the Loader seam (credential.LoadSystemd in
// production). A stub that resolved secret placeholders to fixed
// placeholder text would, if it ever reached a real render, publish a
// config whose credentials are non-secrets — silently producing a
// broken, insecure deployment instead of failing closed. Tests inject
// a synthetic bundle through Options.Loader instead.

// replaceAllChecked substitutes every occurrence of placeholder with v.
// The credential loader guarantees v contains no line breaks or
// control characters, so substitution cannot inject config structure;
// this helper adds the fixed post-condition that the placeholder is
// fully consumed.
func replaceAllChecked(s, placeholder, v string) string {
	out := ""
	rest := s
	for {
		i := indexOf(rest, placeholder)
		if i < 0 {
			return out + rest
		}
		out += rest[:i] + v
		rest = rest[i+len(placeholder):]
	}
}

// indexOf is strings.Index; kept as a tiny indirection so the
// substitution hot path reads declaratively next to its contract.
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// containsDanglingPlaceholder reports whether s contains a "${" with
// no closing "}" after it. validateTemplate's variable extraction
// silently drops such fragments, so the credential phase double-checks
// before output is produced.
func containsDanglingPlaceholder(s string) bool {
	for {
		i := indexOf(s, "${")
		if i < 0 {
			return false
		}
		rest := s[i+2:]
		j := indexOf(rest, "}")
		if j < 0 {
			return true
		}
		s = rest[j+1:]
	}
}
