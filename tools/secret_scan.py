#!/usr/bin/env python3
"""Reproducible local secret scanner for the private_proxy repository.

Phase 0 governance tool (GOV-01). Runs offline, depends only on the Python 3
standard library, and produces deterministic results for a given tree.

Modes:
  default      scan --root (default: repository root) and report findings
  --self-test  scan the synthetic fixtures and assert expected outcomes

Exit codes: 0 = clean / self-test passed, 1 = findings or self-test failed,
2 = usage or internal error.

Suppression: a line may be annotated with the directive
    # secret-scan:allow-line <reason>
in which case findings on that line are reported as suppressed but do not
fail the scan. The reason text is mandatory; a directive without a reason is
itself reported as a finding.

Output policy: a finding is reported by path, line number, rule id and
description, and suppression state/reason only. The matched token, the
assignment value, URL userinfo, and any excerpt of the source line are never
printed. The self-test captures scanner output for the synthetic corpora and
asserts that none of the synthetic values appear in it.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import math
import os
import re
import sys
from dataclasses import dataclass

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Directories never scanned (fixtures are covered by --self-test instead).
EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    ".idea",
    ".vscode",
}

# Synthetic corpus excluded from the default scan so that a clean result is
# meaningful; it is validated separately by --self-test, and the exclusion is
# always announced in the scan output -- never silent.
FIXTURE_DIRS = {
    os.path.join(REPO_ROOT, "tests", "fixtures", "secret_scan"),
}

FIXTURE_DIR = os.path.join(REPO_ROOT, "tests", "fixtures", "secret_scan")

TEXT_SUFFIXES = {
    "", ".txt", ".md", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
    ".conf", ".py", ".sh", ".bash", ".zsh", ".env", ".example", ".tmpl",
    ".template", ".service", ".timer", ".pem", ".key", ".crt", ".properties",
    ".gitignore", ".editorconfig", ".xml", ".html", ".js", ".ts", ".go",
    ".rs", "SUMS", ".lock",
}

ALLOW_DIRECTIVE = re.compile(r"secret-scan:allow-line\s*(.*)$")

# Values that are documentation placeholders, never real secrets.
PLACEHOLDER_VALUE = re.compile(
    r"""^(?:
        <[^<>\n]{1,64}>                       |  # <REDACTED_X>, <domain>
        \$\{[A-Z0-9_]{1,64}\}                 |  # ${TROJAN_PASSWORD_1}
        \$[A-Z][A-Z0-9_]{0,63}                |  # $TROJAN_PASSWORD_1
        (?:CHANGE|REPLACE|INSERT|FILL|EDIT)[_-]?(?:ME|THIS|IN)?  |
        (?:your|my|the|a|an|some|real|actual|insert|replace|paste)[-_a-z0-9.]*  |
        x{3,}|\*{3,}|\.{3,}|-{2,}|_{3,}      |
        (?:redacted|placeholder|example|sample|dummy|fixme|todo|tbd|n/a|none|
           changeme|notreal|fake|dummyvalue)(?:[_-][a-z0-9]+)*
    )$""",
    re.IGNORECASE | re.VERBOSE,
)


@dataclass
class Rule:
    rid: str
    description: str
    pattern: "re.Pattern[str]"


def _rule(rid: str, description: str, pattern: str, flags: int = 0) -> Rule:
    return Rule(rid, description, re.compile(pattern, flags))


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in freq.values())


def looks_placeholder(value: str) -> bool:
    v = value.strip().strip('"\'').strip()
    if not v:
        return True
    if PLACEHOLDER_VALUE.match(v):
        return True
    return False


STRUCTURED_RULES = [
    _rule("aws-access-key", "AWS access key id",
          r"\bAKIA[0-9A-Z]{16}\b"),
    _rule("github-token", "GitHub token (ghp_/gho_/ghu_/ghs_/ghr_)",
          r"\bgh[poshur]_[A-Za-z0-9]{36,255}\b"),
    _rule("github-fine-grained", "GitHub fine-grained PAT",
          r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    _rule("gitlab-token", "GitLab personal access token",
          r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    _rule("slack-token", "Slack token",
          r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    _rule("google-api-key", "Google API key",
          r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    _rule("telegram-bot-token", "Telegram bot token",
          r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b"),
    _rule("private-key-block", "Private key material",
          r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----"),
    _rule("jwt", "Hardcoded JSON Web Token",
          r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    _rule("url-credentials", "URL with embedded credentials",
          r"\b[a-z][a-z0-9+.\-]*://[^/\s:@\"'<>]{1,64}:[^/\s@\"'<>]{3,}@[A-Za-z0-9.\-]+"),
]

GENERIC_RULES = [
    _rule("generic-secret-assignment", "High-entropy secret assignment",
          r"(?i)\b(password|passwd|pwd|secret|token|api[_\-]?key|auth)\b\s*[:=]\s*"
          r"([\"'])?([^\"'\n]{1,256})(\2)?"),
]


def is_high_entropy_secret(value: str) -> bool:
    v = value.strip()
    if len(v) < 16 or len(v) > 128:
        return False
    # Only a whole-value documented placeholder may bypass the generic rule.
    # An embedded placeholder inside a larger value (e.g. a real secret
    # concatenated with `${X}`) must NOT bypass detection.
    if looks_placeholder(v):
        return False
    has_digit = any(c.isdigit() for c in v)
    has_alpha = any(c.isalpha() for c in v)
    if not (has_digit and has_alpha):
        return False
    if shannon_entropy(v) < 3.5:
        return False
    if re.search(r"\s", v):
        return False
    return True


@dataclass
class Finding:
    path: str
    line_no: int
    rid: str
    description: str
    snippet: str  # matched value; internal only, never printed
    suppressed: bool
    suppression_reason: str = ""


def url_credentials_is_placeholder(match: "re.Match[str]") -> bool:
    url = match.group(0)
    cred = url.split("://", 1)[1]
    userinfo = cred.rsplit("@", 1)[0]
    if ":" not in userinfo:
        return False
    password = userinfo.split(":", 1)[1]
    return looks_placeholder(password)


def scan_line(line: str) -> list[tuple[str, str, str]]:
    hits: list[tuple[str, str, str]] = []
    structured_spans: list[tuple[int, int]] = []
    for rule in STRUCTURED_RULES:
        for m in rule.pattern.finditer(line):
            if rule.rid == "url-credentials" and url_credentials_is_placeholder(m):
                continue
            hits.append((rule.rid, rule.description, m.group(0)))
            structured_spans.append(m.span())
    for rule in GENERIC_RULES:
        for m in rule.pattern.finditer(line):
            if any(m.start() < end and start < m.end()
                   for start, end in structured_spans):
                continue  # already covered by a structured rule
            value = m.group(3)
            # `gateway-node-01:${VAR}` etc.: a documented node identity with an
            # embedded placeholder. Documented in the allowed corpus.
            if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,31}:\$\{[A-Z0-9_]{1,64}\}",
                            value.strip()):
                continue
            if is_high_entropy_secret(value):
                hits.append((rule.rid, rule.description, value))
    return hits


def scan_file(path: str, display_root: str) -> tuple[list[Finding], str | None]:
    findings: list[Finding] = []
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        return [], f"unreadable: {exc}"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return [], None  # binary file: skip
    rel = os.path.relpath(path, display_root)
    for idx, line in enumerate(text.splitlines(), start=1):
        directive = ALLOW_DIRECTIVE.search(line)
        reason = ""
        suppressed = False
        if directive:
            reason = directive.group(1).strip().strip("*/#")
            if reason:
                suppressed = True
            else:
                findings.append(Finding(
                    rel, idx, "invalid-allow-directive",
                    "allow-line directive without a reason", line.strip(), False))
        for rid, desc, value in scan_line(line):
            findings.append(Finding(
                rel, idx, rid, desc, value, suppressed, reason))
    return findings, None


def iter_files(root: str):
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in EXCLUDED_DIRS
            and os.path.join(dirpath, d) not in FIXTURE_DIRS
        )
        for name in sorted(filenames):
            if name == ".DS_Store":
                continue
            path = os.path.join(dirpath, name)
            suffix = os.path.splitext(name)[1].lower()
            if name in ("SHA256SUMS", "SHA256SUMS.sig"):
                yield path
            elif suffix in TEXT_SUFFIXES:
                yield path


def scan_tree(root: str) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []
    for path in iter_files(root):
        file_findings, err = scan_file(path, root)
        findings.extend(file_findings)
        if err:
            errors.append(f"{os.path.relpath(path, root)}: {err}")
    return findings, errors


def report(findings: list[Finding], errors: list[str], root: str) -> int:
    active = [f for f in findings if not f.suppressed]
    suppressed = [f for f in findings if f.suppressed]
    for f in findings:
        marker = "SUPPRESSED" if f.suppressed else "FINDING"
        suffix = f" (reason: {f.suppression_reason})" if f.suppressed else ""
        print(f"[{marker}] {f.path}:{f.line_no} {f.rid}: {f.description}"
              f"{suffix}")
    for e in errors:
        print(f"[ERROR] {e}")
    print_exclusion_notice(root)
    print(f"\nscanned root: {root}")
    print(f"findings: {len(active)} active, {len(suppressed)} suppressed, "
          f"{len(errors)} errors")
    return 1 if (active or errors) else 0


def print_exclusion_notice(root: str) -> None:
    """Announce the fixture exclusion whenever this scan's traversal would
    have covered (any part of) the fixture corpus but did not, for any scan
    root -- not just the repository root."""
    root = os.path.abspath(root)
    for fixture_dir in sorted(FIXTURE_DIRS):
        fixture_dir = os.path.abspath(fixture_dir)
        if not os.path.isdir(fixture_dir):
            continue
        # The fixture dir is inside the scan root (or is the scan root) and
        # therefore would be traversed without the exclusion.
        covered = (fixture_dir == root
                   or fixture_dir.startswith(root + os.sep))
        if covered:
            print("note: synthetic fixture corpus excluded from this scan; "
                  "validate it with `python3 tools/secret_scan.py "
                  "--self-test`")
            return


def self_test() -> int:
    positives_dir = os.path.join(FIXTURE_DIR, "positives")
    allowed_dir = os.path.join(FIXTURE_DIR, "allowed")
    if not os.path.isdir(positives_dir) or not os.path.isdir(allowed_dir):
        print("self-test: fixture directories missing under "
              f"{FIXTURE_DIR}", file=sys.stderr)
        return 1

    failures: list[str] = []
    checked_rules: set[str] = set()

    for name in sorted(os.listdir(positives_dir)):
        path = os.path.join(positives_dir, name)
        if not os.path.isfile(path):
            continue
        expected_rules = expected_rules_for(name)
        findings, errors = scan_file(path, positives_dir)
        if errors:
            failures.append(f"{name}: scan error {errors}")
            continue
        active = [f for f in findings if not f.suppressed]
        hit_rules = {f.rid for f in active}
        missing = expected_rules - hit_rules
        if missing:
            failures.append(f"{name}: expected rule(s) {sorted(missing)} "
                            "not detected")
        checked_rules |= expected_rules
        unexpected = hit_rules - expected_rules
        if unexpected:
            failures.append(f"{name}: unexpected rule(s) {sorted(unexpected)}")
        if not active:
            failures.append(f"{name}: no active findings (expected >= 1)")

    for name in sorted(os.listdir(allowed_dir)):
        path = os.path.join(allowed_dir, name)
        if not os.path.isfile(path):
            continue
        findings, errors = scan_file(path, allowed_dir)
        active = [f for f in findings if not f.suppressed]
        if errors:
            failures.append(f"{name}: scan error {errors}")
        elif active:
            for f in active:
                failures.append(f"{name}: false positive {f.rid} "
                                f"at line {f.line_no}")

    all_rule_ids = {r.rid for r in STRUCTURED_RULES + GENERIC_RULES}
    uncovered = all_rule_ids - checked_rules - {"generic-secret-assignment"}
    # generic-secret-assignment is exercised via the password fixture; all
    # structured rules must each be exercised by at least one positive.
    if uncovered:
        failures.append(f"rules never exercised by fixtures: {sorted(uncovered)}")

    # Output-leak assertion: capture real scanner output for both corpora and
    # prove (a) no source line and (b) no internal finding snippet / matched
    # token appears in it. Snippets are the exact values the rules matched;
    # asserting on them directly proves token values are never printed.
    for corpus_dir in (positives_dir, allowed_dir):
        output = capture_report(corpus_dir)
        for name in sorted(os.listdir(corpus_dir)):
            path = os.path.join(corpus_dir, name)
            if not os.path.isfile(path):
                continue
            with open(path, "r", encoding="utf-8") as fh:
                for idx, line in enumerate(fh.read().splitlines(), start=1):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if stripped in output:
                        failures.append(
                            f"output leak: {name}:{idx} source line "
                            "appeared in scanner output")
        corpus_findings, _ = scan_tree(corpus_dir)
        for f in corpus_findings:
            if f.snippet and f.snippet in output:
                failures.append(
                    f"output leak: {f.path}:{f.line_no} matched token "
                    f"for rule {f.rid} appeared in scanner output")
    # The captured output must actually contain findings for the positives
    # corpus, otherwise the leak assertion above would be vacuous.
    positive_output = capture_report(positives_dir)
    if "FINDING" not in positive_output:
        failures.append("output capture for positives corpus contains no "
                        "findings; leak assertion is vacuous")
    if "SUPPRESSED" not in capture_report(allowed_dir):
        failures.append("output capture for allowed corpus contains no "
                        "suppressed finding; suppression path not exercised")

    if failures:
        print("self-test: FAILED")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("self-test: OK (all synthetic positives detected, "
          "allowed placeholders clean, every structured rule exercised, "
          "no synthetic value present in scanner output)")
    return 0


def capture_report(root: str) -> str:
    findings, errors = scan_tree(root)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        report(findings, errors, root)
    return buf.getvalue()


def expected_rules_for(name: str) -> set[str]:
    table = {
        "aws.txt": {"aws-access-key"},
        "github.txt": {"github-token"},
        "github_fine_grained.txt": {"github-fine-grained"},
        "gitlab.txt": {"gitlab-token"},
        "slack.txt": {"slack-token"},
        "google.txt": {"google-api-key"},
        "telegram.txt": {"telegram-bot-token"},
        "private_key.pem": {"private-key-block"},
        "jwt.txt": {"jwt"},
        "url_credentials.txt": {"url-credentials"},
        "generic_password.yaml": {"generic-secret-assignment"},
        "placeholder_concat.txt": {"generic-secret-assignment"},
    }
    return table.get(name, set())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="local secret scanner")
    parser.add_argument("--root", default=REPO_ROOT,
                        help="root directory to scan (default: repo root)")
    parser.add_argument("--self-test", action="store_true",
                        help="run fixture self-test instead of scanning")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"error: root not found: {root}", file=sys.stderr)
        return 2
    findings, errors = scan_tree(root)
    return report(findings, errors, root)


if __name__ == "__main__":
    sys.exit(main())
