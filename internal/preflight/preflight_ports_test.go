package preflight

import (
	"errors"
	"strings"
	"testing"
)

// listenerProbe is the fakeProbe boundary extended with listener facts.
// It re-declares the full Probe surface so the ports tests stay focused
// and self-contained.
type listenerProbe struct {
	envCalls       int
	diskCalls      int
	identityCalls  int
	listenersCalls int

	envErr       error
	avail        uint64
	diskErr      error
	identity     IdentityFacts
	identityErr  error
	listeners    []Listener
	listenersErr error
}

func (p *listenerProbe) Environment() error {
	p.envCalls++
	return p.envErr
}

func (p *listenerProbe) AvailableBytes() (uint64, error) {
	p.diskCalls++
	return p.avail, p.diskErr
}

func (p *listenerProbe) Identity() (IdentityFacts, error) {
	p.identityCalls++
	return p.identity, p.identityErr
}

func (p *listenerProbe) Listeners() ([]Listener, error) {
	p.listenersCalls++
	return p.listeners, p.listenersErr
}

// goodListenerProbe returns a fake whose facts satisfy all checks and
// whose listener list is empty.
func goodListenerProbe() *listenerProbe {
	return &listenerProbe{avail: minFreeBytes, identity: goodIdentity()}
}

// TestPreflightPortsConflictTargets proves only exact role-reserved
// protocol+port pairs are conflict targets: unrelated ports and the
// same port on the wrong protocol are ignored, while any listener on
// an exact pair is a conflict regardless of address.
func TestPreflightPortsConflictTargets(t *testing.T) {
	cases := []struct {
		name      string
		role      string
		listeners []Listener
		want      string
	}{
		{"gateway no listeners passes", "gateway", nil, "pass"},
		{"gateway unrelated high port ignored (e.g. a dev service)", "gateway",
			[]Listener{{Protocol: "tcp", Address: "127.0.0.1", Port: 9999}}, "pass"},
		{"gateway ssh port ignored", "gateway",
			[]Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 22}}, "pass"},
		{"gateway nginx 443 tcp ignored (reserved is udp for egress, nothing for gateway)", "gateway",
			[]Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 443}}, "pass"},
		{"gateway same port wrong protocol ignored (udp 8443 is not a target)", "gateway",
			[]Listener{{Protocol: "udp", Address: "0.0.0.0", Port: 8443}}, "pass"},
		{"gateway 8443 tcp loopback conflicts", "gateway",
			[]Listener{{Protocol: "tcp", Address: "127.0.0.1", Port: 8443}}, "fail"},
		{"gateway 8443 tcp public address conflicts (no address approval)", "gateway",
			[]Listener{{Protocol: "tcp", Address: "203.0.113.10", Port: 8443}}, "fail"},
		{"gateway 8443 tcp wildcard conflicts", "gateway",
			[]Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 8443}}, "fail"},
		{"gateway 8443 tcp IPv6 wildcard conflicts", "gateway",
			[]Listener{{Protocol: "tcp", Address: "::", Port: 8443}}, "fail"},
		{"gateway public 8444 edge ignored", "gateway",
			[]Listener{{Protocol: "tcp", Address: "198.51.100.7", Port: 8444}}, "pass"},
		{"gateway 18444 tcp loopback occupied conflicts", "gateway",
			[]Listener{{Protocol: "tcp", Address: "127.0.0.1", Port: 18444}}, "fail"},
		{"gateway 18444 tcp wildcard violates loopback policy", "gateway",
			[]Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 18444}}, "fail"},
		{"gateway 7890 tcp loopback occupied conflicts", "gateway",
			[]Listener{{Protocol: "tcp", Address: "127.0.0.1", Port: 7890}}, "fail"},
		{"gateway 7890 tcp IPv6 loopback occupied conflicts", "gateway",
			[]Listener{{Protocol: "tcp", Address: "::1", Port: 7890}}, "fail"},
		{"gateway 7890 tcp IPv4 wildcard bind flagged (loopback-only policy)", "gateway",
			[]Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 7890}}, "fail"},
		{"gateway 7890 tcp IPv6 wildcard bind flagged (loopback-only policy)", "gateway",
			[]Listener{{Protocol: "tcp", Address: "::", Port: 7890}}, "fail"},
		{"gateway 7890 tcp public bind flagged (loopback-only policy)", "gateway",
			[]Listener{{Protocol: "tcp", Address: "203.0.113.10", Port: 7890}}, "fail"},
		{"gateway 17894 tcp loopback occupied conflicts", "gateway",
			[]Listener{{Protocol: "tcp", Address: "127.0.0.1", Port: 17894}}, "fail"},
		{"gateway 17894 udp loopback occupied conflicts", "gateway",
			[]Listener{{Protocol: "udp", Address: "127.0.0.1", Port: 17894}}, "fail"},
		{"gateway 17894 tcp wildcard violates loopback policy", "gateway",
			[]Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 17894}}, "fail"},
		{"gateway 17894 udp public bind violates loopback policy", "gateway",
			[]Listener{{Protocol: "udp", Address: "203.0.113.10", Port: 17894}}, "fail"},
		{"egress no listeners passes", "egress", nil, "pass"},
		{"egress hysteria target udp 443 occupied conflicts", "egress",
			[]Listener{{Protocol: "udp", Address: "198.51.100.7", Port: 443}}, "fail"},
		{"egress udp 443 wildcard conflicts", "egress",
			[]Listener{{Protocol: "udp", Address: "::", Port: 443}}, "fail"},
		{"egress tcp 443 same port wrong protocol ignored (nginx)", "egress",
			[]Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 443}}, "pass"},
		{"egress unrelated port ignored (frp)", "egress",
			[]Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 7000}}, "pass"},
		{"unparseable address on reserved pair conflicts", "gateway",
			[]Listener{{Protocol: "tcp", Address: "not-an-ip", Port: 8443}}, "fail"},
		{"unparseable address off reserved ports ignored", "gateway",
			[]Listener{{Protocol: "tcp", Address: "not-an-ip", Port: 9999}}, "pass"},
		{"unknown protocol ignored", "gateway",
			[]Listener{{Protocol: "sctp", Address: "127.0.0.1", Port: 8443}}, "pass"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := goodListenerProbe()
			probe.listeners = tc.listeners
			res := runOnline(t, tc.role, probe)
			if probe.listenersCalls != 1 {
				t.Fatalf("listeners probe called %d times; want 1", probe.listenersCalls)
			}
			c := findCheck(res, "ports")
			if c == nil {
				t.Fatal("ports check missing")
			}
			if c.Status != tc.want {
				t.Errorf("ports = %q (%s); want %q", c.Status, c.Detail, tc.want)
			}
			// No listener fact may ever leak into the detail.
			for _, l := range tc.listeners {
				if l.Address != "" && strings.Contains(c.Detail, l.Address) {
					t.Errorf("listener address %q leaked into detail: %q", l.Address, c.Detail)
				}
			}
		})
	}
}

// TestPreflightPortsLoopbackOnlyDetail proves a loopback-only reserved
// port bound to a non-loopback or wildcard address produces the
// specific loopback-scope failure detail, not the generic conflict.
func TestPreflightPortsLoopbackOnlyDetail(t *testing.T) {
	probe := goodListenerProbe()
	probe.listeners = []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 7890}}
	res := runOnline(t, "gateway", probe)
	c := findCheck(res, "ports")
	if c == nil || c.Status != "fail" {
		t.Fatalf("ports check = %+v; want fail", c)
	}
	if !strings.Contains(c.Detail, "loopback") {
		t.Errorf("wildcard bind of loopback-only port lacks loopback detail: %q", c.Detail)
	}
}

// TestPreflightPortsProbeErrorNoLeak proves a listener scan error is a
// stable failure without the canary text.
func TestPreflightPortsProbeErrorNoLeak(t *testing.T) {
	probe := goodListenerProbe()
	probe.listenersErr = errors.New("read /proc/net/tcp on canary-kernel-5.15: permission denied")
	res := runOnline(t, "egress", probe)
	c := findCheck(res, "ports")
	if c == nil || c.Status != "fail" {
		t.Fatalf("ports check = %+v; want fail", c)
	}
	for _, tok := range []string{"canary-kernel", "/proc", "permission denied", "5.15"} {
		if strings.Contains(c.Detail, tok) {
			t.Errorf("listener error token %q leaked into detail: %q", tok, c.Detail)
		}
	}
}

// TestPreflightOfflineZeroListenerCalls proves offline mode never
// invokes the Listeners probe method and keeps the static ports check.
func TestPreflightOfflineZeroListenerCalls(t *testing.T) {
	probe := goodListenerProbe()
	probe.listenersErr = errors.New("canary must never be reached")
	res, err := Run(Options{Role: "gateway", Offline: true, Probe: probe})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if probe.listenersCalls != 0 {
		t.Errorf("offline mode invoked Listeners %d times; want 0", probe.listenersCalls)
	}
	if probe.envCalls != 0 || probe.diskCalls != 0 || probe.identityCalls != 0 {
		t.Errorf("offline mode invoked other probe methods: env=%d disk=%d identity=%d",
			probe.envCalls, probe.diskCalls, probe.identityCalls)
	}
	c := findCheck(res, "ports")
	if c == nil || c.Status != "pass" {
		t.Errorf("offline ports check = %+v; want pass (static matrix)", c)
	}
}
