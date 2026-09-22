//go:build linux

package preflight

// defaultProbe returns the real read-only Linux probe.
func defaultProbe() Probe { return linuxProbe{} }
