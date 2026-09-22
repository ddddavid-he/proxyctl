package render

import (
	"strings"
	"testing"

	"proxyctl/internal/config"
	"proxyctl/internal/credential"
	"proxyctl/internal/safex"
)

// fakeBundle is an in-memory BundleSource: pure, platform-independent.
type fakeBundle struct{ scalars map[string]string }

func (f fakeBundle) Scalar(name string) (string, bool) {
	v, ok := f.scalars[name]
	return v, ok
}

func (f fakeBundle) Materialize() []credential.MaterializedAsset { return nil }

// mustParseConfig parses a config document for the config phase.
func mustParseConfig(t *testing.T, role config.Role, text string) *config.Document {
	t.Helper()
	doc, err := config.Parse(text, role)
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}
	return doc
}

// requireCode asserts err is a *safex.Error with the wanted code.
func requireCode(t *testing.T, err error, want safex.Code) {
	t.Helper()
	se, ok := err.(*safex.Error)
	if !ok {
		t.Fatalf("error = %T %v, want *safex.Error code %v", err, err, want)
	}
	if se.Code != want {
		t.Fatalf("error code = %v, want %v (message %q)", se.Code, want, se.Message)
	}
}

// requireNoCanary asserts the error message contains no secret-shaped
// values, canaries or control characters — fixed diagnostics only.
func requireNoCanary(t *testing.T, err error) {
	t.Helper()
	se, ok := err.(*safex.Error)
	if !ok {
		t.Fatalf("error = %T, want *safex.Error", err)
	}
	msg := se.Error()
	if se.Unwrap() != nil {
		t.Errorf("error must not wrap underlying detail: %q", msg)
	}
	if strings.Contains(msg, "CANARY-VALUE") {
		t.Errorf("error leaks canary value: %q", msg)
	}
	if strings.ContainsAny(msg, "\r\n\t") {
		t.Errorf("error contains control characters: %q", msg)
	}
	if strings.Contains(msg, "hunter2") || strings.Contains(msg, "p@ss") {
		t.Errorf("error leaks a secret-shaped value: %q", msg)
	}
}
