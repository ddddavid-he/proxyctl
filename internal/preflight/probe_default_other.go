//go:build !linux

package preflight

// defaultProbe returns the fail-closed stub on non-Linux platforms:
// with no real probe available, fact-dependent checks must not pass.
func defaultProbe() Probe { return stubProbe{} }
