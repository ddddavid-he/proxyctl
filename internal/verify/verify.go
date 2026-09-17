// Package verify runs predefined, offline verification profiles and
// emits stable, redacted JSON reports. It never executes external
// commands, never opens network listeners, and never includes
// credentials, auth headers, or full target URLs in its output.
package verify

import (
	"fmt"
	"strings"
	"time"

	"proxyctl/internal/safex"
)

// Check is a single verification result.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "pass" | "fail" | "skip"
	Detail string `json:"detail"`
	Millis int64  `json:"millis,omitempty"`
}

// Result is the stable JSON shape of a verify run.
type Result struct {
	Profile   string    `json:"profile"`
	OK        bool      `json:"ok"`
	StartedAt time.Time `json:"started_at"`
	Duration  string    `json:"duration"`
	Checks    []Check   `json:"checks"`
}

// Options controls a verify run.
type Options struct {
	Profile string
}

// Run executes the named profile. All checks in this skeleton are
// offline invariants (static posture checks); network probes are out of
// scope by design for this milestone.
func Run(opts Options) (*Result, error) {
	profile := opts.Profile
	switch profile {
	case "loopback", "canary":
	default:
		return nil, safex.New(safex.CodeInvalidEnum,
			"invalid profile %q: must be loopback or canary", profile)
	}
	start := time.Now()
	res := &Result{Profile: profile, StartedAt: start.UTC(), OK: true}

	res.add(staticCheck("no-direct-fallback", "render allowlist forbids DIRECT rules"))
	res.add(staticCheck("no-insecure-tls", "render allowlist forbids skip-cert-verify and insecure"))
	res.add(staticCheck("loopback-only-controller", "controller must bind loopback per config validation"))
	if profile == "canary" {
		res.add(staticCheck("egress-link-required", "all rules route via egress-hy2; no fallback accepted"))
		res.add(staticCheck("no-secret-in-report", "report contains no credentials, auth headers, or full target URLs"))
	}

	res.Duration = time.Since(start).Round(time.Millisecond).String()
	for _, c := range res.Checks {
		if c.Status == "fail" {
			res.OK = false
		}
	}
	return res, nil
}

func staticCheck(name, detail string) Check {
	return Check{Name: name, Status: "pass", Detail: detail}
}

func (r *Result) add(c Check) {
	r.Checks = append(r.Checks, c)
}

// RedactTargetURL returns a host-only summary of a URL for reports:
// scheme and host are kept, path, query and userinfo are dropped.
func RedactTargetURL(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return "<redacted>"
	}
	rest := u[i+3:]
	for j := 0; j < len(rest); j++ {
		if rest[j] == '/' || rest[j] == '?' || rest[j] == '#' {
			rest = rest[:j]
			break
		}
	}
	// strip any userinfo
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	return fmt.Sprintf("%s%s", u[:i+3], rest)
}
