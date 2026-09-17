// Package preflight implements read-only pre-deployment checks.
//
// This package performs NO DNS resolution, NO ACME or certificate
// provider call, NO certificate issuance or renewal and NO read of any
// real host certificate. Host facts come from an injectable Probe
// boundary (on Linux, read-only reads of fixed /proc and /etc paths),
// and DNS/certificate facts come from an injectable NetProbe boundary
// whose production default reports unavailability — so the name and
// certificate gates fail closed instead of passing on absent evidence.
//
// With --offline no Probe or NetProbe method is invoked at all: an
// offline run makes exactly zero DNS and certificate probe calls.
//
// All probe output is untrusted input: it is validated structurally,
// compared against fixed code allowlists, and never echoed into a check
// detail. No check claims that a host or a domain is "configured", and
// DNS evidence is never treated as certificate proof.
package preflight

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"proxyctl/internal/config"
	"proxyctl/internal/safex"
)

// Check is a single named, redacted check result.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "pass" | "fail" | "skip"
	Detail string `json:"detail"`
}

// Result is the stable JSON shape of a preflight run.
type Result struct {
	Role    string  `json:"role"`
	Offline bool    `json:"offline"`
	OK      bool    `json:"ok"`
	Checks  []Check `json:"checks"`
}

// Listener is one observed socket listener, represented as typed,
// deterministic facts (protocol, numeric address, port) rather than
// free-form command output.
type Listener struct {
	Protocol string // "tcp" | "udp"
	Address  string // numeric IP literal, e.g. "127.0.0.1", "::"
	Port     uint16
}

// IdentityFacts are typed facts about the intended runtime service
// account and the planned ephemeral runtime directory.
type IdentityFacts struct {
	Name       string      // account name of the intended service account
	UID        int         // numeric UID the account resolves to on this host
	GID        int         // numeric GID the account resolves to on this host
	DirMode    os.FileMode // permission bits of the runtime directory
	DirUID     int         // numeric owner of the runtime directory
	DirGID     int         // numeric group of the runtime directory
	DirMissing bool        // true when the runtime directory does not exist
}

// Probe is the explicit online environment boundary for preflight. Its
// methods are the ONLY operations allowed to touch the live
// environment; they are never invoked in offline mode. Methods take no
// path or command arguments: preflight never accepts arbitrary probe
// paths or shell commands. All returned data is treated as untrusted
// input and all error text is replaced with fixed, non-leaking
// messages.
type Probe interface {
	// Environment probes the online environment boundary. A nil error
	// means the boundary is healthy.
	Environment() error
	// AvailableBytes returns free bytes at the fixed runtime target
	// directory.
	AvailableBytes() (uint64, error)
	// Identity returns facts about the intended service account and the
	// runtime directory mode/ownership.
	Identity() (IdentityFacts, error)
	// Listeners returns the current socket listeners.
	Listeners() ([]Listener, error)
}

// stubProbe is the fallback Probe used when Options.Probe is nil on a
// platform without a real default probe. It performs no network access
// and reports no host facts, so any check requiring facts fails closed
// (details withheld). On Linux the nil-Probe default is the real
// read-only /proc probe instead; see probe_linux.go.
type stubProbe struct{}

func (stubProbe) Environment() error { return nil }

func (stubProbe) AvailableBytes() (uint64, error) {
	return 0, safex.New(safex.CodeIO, "host facts unavailable with default probe")
}

func (stubProbe) Identity() (IdentityFacts, error) {
	return IdentityFacts{}, safex.New(safex.CodeIO, "host facts unavailable with default probe")
}

func (stubProbe) Listeners() ([]Listener, error) {
	return nil, safex.New(safex.CodeIO, "host facts unavailable with default probe")
}

// Fixed runtime contract constants. Probe methods never take paths or
// commands, so these values cannot be influenced by callers or by
// (untrusted) probe data.
const (
	// runtimeTargetDir is the planned ephemeral runtime directory the
	// disk and identity checks apply to.
	runtimeTargetDir = "/run/private-proxy"
	// minFreeBytes is the documented minimum free space at the runtime
	// target (64 MiB).
	minFreeBytes = uint64(64) << 20
	// expectedServiceAccount is the fixed name of the intended non-root
	// service account. Numeric IDs are NOT hardcoded: Debian may assign
	// any UID/GID to the account; the stable identity fact is the name.
	expectedServiceAccount = "privateproxy"
	// expectedRuntimeDirMode is the required restrictive permission
	// mask of the runtime directory.
	expectedRuntimeDirMode = os.FileMode(0o700)
)

// Options controls a preflight run.
type Options struct {
	Role    string
	Offline bool
	// ConfigPath optionally points at the role config for static checks.
	ConfigPath string
	// Probe optionally injects the online environment boundary. Nil
	// selects the platform default probe (on Linux, the real read-only
	// /proc probe; elsewhere a no-network stub that fails closed).
	// Probe methods are never invoked when Offline is true.
	Probe Probe

	// NetProbe optionally injects the DNS/certificate evidence
	// boundary. Nil selects unavailableNetProbe, which performs NO DNS
	// resolution, NO ACME or provider call and NO certificate read, and
	// reports unavailability — so the name and certificate checks fail
	// closed by default. NetProbe methods are never invoked when
	// Offline is true.
	//
	// Targets come from the role's fixed code allowlist only: neither
	// this option nor the CLI can supply a hostname, URL, path, command
	// or resolver.
	NetProbe NetProbe

	// now optionally fixes the evaluation instant for certificate
	// validity. It is UNEXPORTED so only tests in this package can set
	// it: production always evaluates against the real clock, and no
	// caller can backdate an expiry check. Zero means time.Now().
	now time.Time

	// arch optionally fixes the binary architecture for deterministic
	// tests. It is unexported so production callers always use
	// runtime.GOARCH.
	arch string
}

// Run executes the preflight checks for the given options. All static
// checks are read-only. In offline mode Probe methods are never
// invoked; in online mode all environment interaction is delegated
// entirely to the injected Probe boundary (a nil Probe selects the
// platform default probe).
func Run(opts Options) (*Result, error) {
	// Role is validated first and strictly: unknown roles never reach
	// any check logic.
	if _, err := config.ParseRole(opts.Role); err != nil {
		return nil, err
	}
	res := &Result{Role: opts.Role, Offline: opts.Offline, OK: true}

	// 1. arch: document expected vs current
	res.check("arch", checkArch(opts.Role, opts.arch))

	// 2. ports: offline reports the static reservation matrix only; the
	// online conflict scan runs against the Probe boundary below.
	if opts.Offline {
		res.check("ports", checkPortsOffline(opts.Role))
	}

	// 3. secrets presence: render-time credential placeholders
	res.check("credentials", checkCredentialsPlaceholder(opts))

	// 4. fail-closed posture marker
	res.check("fail-closed", Check{Status: "pass", Detail: "no DIRECT fallback accepted by render allowlist"})

	// 5. online environment boundary: probe only when not offline. All
	// probe facts and errors are untrusted; every failure is replaced
	// with a fixed, non-leaking message.
	if !opts.Offline {
		probe := opts.Probe
		if probe == nil {
			probe = defaultProbe()
		}
		res.check("environment", checkEnvironment(probe))
		res.check("disk", checkDisk(probe))
		res.check("runtime-identity", checkRuntimeIdentity(probe))
		res.check("ports", checkPorts(opts.Role, probe))

		// DNS and certificate evidence are two INDEPENDENT checks over
		// the role's fixed target allowlist. A nil NetProbe selects the
		// unavailable default, so both fail closed rather than passing
		// on absent evidence. Neither check claims a host or domain is
		// configured, and a passing DNS check is never certificate
		// proof.
		// isNilNetProbe covers BOTH a literal nil interface and a
		// TYPED NIL (a non-nil interface wrapping a nil pointer, for
		// which `== nil` is false). Either way the fail-closed default
		// applies, so an absent probe can never panic on a nil receiver
		// and can never be mistaken for a live one.
		netProbe := opts.NetProbe
		if isNilNetProbe(netProbe) {
			netProbe = unavailableNetProbe{}
		}
		now := opts.now
		if now.IsZero() {
			now = time.Now()
		}
		res.check("dns-evidence", checkDNS(opts.Role, netProbe))
		res.check("certificate-evidence", checkCertificate(opts.Role, netProbe, now))
	}

	// 6. offline mode markers
	if opts.Offline {
		res.check("offline-mode", Check{
			Status: "pass",
			Detail: "no DNS, certificate or network probes executed",
		})
	}

	for _, c := range res.Checks {
		if c.Status == "fail" {
			res.OK = false
		}
	}
	return res, nil
}

func (r *Result) check(name string, c Check) {
	if c.Name == "" {
		c.Name = name
	}
	r.Checks = append(r.Checks, c)
}

func checkArch(role, goarch string) Check {
	expect := "arm64"
	if role == "egress" {
		expect = "amd64"
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	if goarch == expect {
		return Check{Status: "pass", Detail: fmt.Sprintf("GOARCH=%s matches role expectation", goarch)}
	}
	return Check{
		Status: "fail",
		Detail: fmt.Sprintf("GOARCH=%s does not match role %s expectation %s (cross-compiled binary or wrong host)", goarch, role, expect),
	}
}

// reservation is one exact protocol+port pair the role intends to
// bind. Any existing listener on an exact pair is a conflict target.
type reservation struct {
	proto        string // "tcp" | "udp"
	port         uint16
	loopbackOnly bool // bind scope policy: must bind loopback only
	label        string
}

// roleReservations is the fixed role-specific reservation matrix:
// gateway TCP 8443/18444/7890 and egress UDP 443. Public HTTPS CONNECT TCP/8444
// is owned by the external OpenResty TLS edge; Mihomo reserves only its fixed
// loopback backend 18444. Bind scope (loopback-only for gateway 18444/7890) is a
// static config policy declared here; it is separate
// from conflict detection and never claims any address is "approved".
func roleReservations(role string) []reservation {
	switch role {
	case "gateway":
		return []reservation{
			{proto: "tcp", port: 8443, label: "8443/tcp (trojan-in)"},
			{proto: "tcp", port: 18444, loopbackOnly: true, label: "18444/tcp (loopback https backend)"},
			{proto: "tcp", port: 7890, loopbackOnly: true, label: "7890/tcp (loopback mixed)"},
		}
	case "egress":
		return []reservation{
			{proto: "udp", port: 443, label: "443/udp (hysteria2)"},
		}
	}
	return nil
}

// checkPortsOffline reports the reservation matrix without any live
// scan (offline mode: zero probe calls).
func checkPortsOffline(role string) Check {
	var labels []string
	for _, r := range roleReservations(role) {
		labels = append(labels, r.label)
	}
	return Check{Status: "pass", Detail: "reserved: " + strings.Join(labels, ", ") + " (offline: no live conflict scan)"}
}

// checkPorts validates current listeners against the exact reserved
// protocol+port pairs for the role. A host legitimately runs other
// services (SSH, nginx, FRP, ...): listeners outside the exact pairs —
// unrelated ports or the same port on the wrong protocol — are
// ignored, never conflicts. Any listener on an exact reserved pair is
// a conflict regardless of address (the service intends to bind it);
// no address is claimed to be approved. Loopback-only reservations
// additionally flag non-loopback/wildcard binds as a static policy
// violation. Failure Details are fixed strings: probe-supplied
// addresses, ports and error text never leak.
func checkPorts(role string, p Probe) Check {
	listeners, err := p.Listeners()
	if err != nil {
		return Check{Status: "fail", Detail: "listener scan failed (details withheld)"}
	}
	for _, l := range listeners {
		proto := strings.ToLower(l.Protocol)
		if proto != "tcp" && proto != "udp" {
			// Not a protocol this tool reserves; not a conflict target.
			continue
		}
		addr, aerr := netip.ParseAddr(strings.TrimSpace(l.Address))
		for _, r := range roleReservations(role) {
			if r.proto != proto || r.port != l.Port {
				continue
			}
			if aerr == nil && r.loopbackOnly && !addr.IsLoopback() {
				return Check{Status: "fail", Detail: "loopback-only reserved port is bound to a non-loopback or wildcard address"}
			}
			return Check{Status: "fail", Detail: "reserved port already has a conflicting listener"}
		}
	}
	return Check{Status: "pass", Detail: "no listener conflicts on reserved ports"}
}

// checkDisk validates free space at the fixed runtime target against
// the documented minimum. Failure Details are fixed strings.
func checkDisk(p Probe) Check {
	avail, err := p.AvailableBytes()
	if err != nil {
		return Check{Status: "fail", Detail: "disk probe failed (details withheld)"}
	}
	if avail < minFreeBytes {
		return Check{Status: "fail", Detail: "insufficient free space at the runtime target (minimum 64 MiB)"}
	}
	return Check{Status: "pass", Detail: "sufficient free space at the runtime target (minimum 64 MiB)"}
}

// checkRuntimeIdentity validates the intended non-root service account
// (by its stable account name; numeric IDs are host-assigned and never
// hardcoded) plus restrictive runtime directory mode and numeric
// ownership matching the probed service UID/GID. Failure Details are
// fixed strings: probed names, UIDs, GIDs and modes never leak.
func checkRuntimeIdentity(p Probe) Check {
	f, err := p.Identity()
	if err != nil {
		return Check{Status: "fail", Detail: "identity probe failed (details withheld)"}
	}
	if f.Name != expectedServiceAccount {
		return Check{Status: "fail", Detail: "service identity does not match the intended service account"}
	}
	if f.UID == 0 || f.GID == 0 {
		return Check{Status: "fail", Detail: "service must not run as root"}
	}
	if f.DirMissing {
		return Check{Status: "fail", Detail: "runtime directory is missing"}
	}
	if f.DirMode.Perm() != expectedRuntimeDirMode {
		return Check{Status: "fail", Detail: "runtime directory mode is not restrictive (want 0700)"}
	}
	if f.DirUID != f.UID || f.DirGID != f.GID {
		return Check{Status: "fail", Detail: "runtime directory ownership does not match the service identity"}
	}
	return Check{Status: "pass", Detail: "non-root service identity and restrictive runtime directory verified"}
}

// checkEnvironment runs the injected online environment probe. The
// failure Detail is a fixed string: the probe error text is untrusted
// (it may carry host details) and is deliberately never surfaced.
func checkEnvironment(p Probe) Check {
	if err := p.Environment(); err != nil {
		return Check{Status: "fail", Detail: "environment probe failed (details withheld)"}
	}
	return Check{Status: "pass", Detail: "environment probe succeeded"}
}

// checkCredentialsPlaceholder verifies the config file, when provided,
// keeps credentials as placeholders (delegating deep validation to
// internal/config).
func checkCredentialsPlaceholder(opts Options) Check {
	if opts.ConfigPath == "" {
		return Check{Status: "skip", Detail: "no config path provided"}
	}
	// Reject traversal components in the config path before reading.
	// Split the RAW path: filepath.Clean would collapse an intermediate
	// ".." (as in "a/../b") and hide the traversal.
	for _, part := range strings.Split(opts.ConfigPath, string(filepath.Separator)) {
		if part == ".." {
			return Check{Status: "fail", Detail: "config path contains '..' traversal component"}
		}
	}
	// The final component is Lstat'ed: symlinks and directories are
	// refused so a caller-supplied path can never read through a
	// symlink escape.
	fi, err := os.Lstat(opts.ConfigPath)
	if err != nil {
		return Check{Status: "fail", Detail: "config path cannot be stat'ed"}
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return Check{Status: "fail", Detail: "config path is a symlink; refusing to read"}
	}
	if fi.IsDir() {
		return Check{Status: "fail", Detail: "config path is a directory, not a file"}
	}
	data, err := os.ReadFile(opts.ConfigPath)
	if err != nil {
		return Check{Status: "fail", Detail: safex.New(safex.CodeIO, "cannot read config").Error()}
	}
	text := string(data)
	for _, field := range []string{"password", "secret", "token"} {
		for _, line := range strings.Split(text, "\n") {
			t := strings.TrimSpace(line)
			low := strings.ToLower(t)
			if strings.Contains(low, field) && strings.Contains(t, ":") {
				v := strings.TrimSpace(t[strings.Index(t, ":")+1:])
				v = strings.Trim(v, `"`)
				if v != "" && !safex.IsPlaceholder(v) && !isKnownSafe(v) {
					return Check{Status: "fail", Detail: safex.Redact(fmt.Sprintf("credential-like field with non-placeholder value near %q", field))}
				}
			}
		}
	}
	return Check{Status: "pass", Detail: "credential fields are placeholders or absent"}
}

// isKnownSafe lists non-secret values allowed next to credential keys.
func isKnownSafe(v string) bool {
	switch v {
	case "true", "false", "userpass", "strict":
		return true
	}
	return false
}
