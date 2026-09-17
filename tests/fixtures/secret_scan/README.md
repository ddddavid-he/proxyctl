# Secret scanner fixtures

Synthetic corpus for `tools/secret_scan.py --self-test`.

- `positives/` — fabricated secret-looking values. Each file must trigger at
  least the rule(s) mapped in `expected_rules_for()` in `tools/secret_scan.py`.
  None of these values are real credentials.
- `allowed/` — placeholder, documentation, and redaction forms that must
  produce zero active findings. Includes an example of the
  `# secret-scan:allow-line <reason>` suppression directive.

The self-test fails if any positive goes undetected, any allowed fixture
produces an active finding, a suppression directive lacks a reason, any
structured rule is not exercised by at least one positive fixture, or any
source line or matched token value appears in captured scanner output.

`positives/placeholder_concat.txt` proves that a high-entropy value with an
embedded `${VAR}` is still detected: only a whole-value documented
placeholder (or the documented `node-id:${VAR}` machine-identity form) may
bypass the generic rule.

`positives/private_key.pem` (and any future fixture `.key`/`.pem`) is
explicitly un-ignored in `.gitignore`
(`!tests/fixtures/secret_scan/positives/*.pem` and
`!tests/fixtures/secret_scan/positives/*.key`) so the synthetic corpus stays
tracked; real `.pem`/`.key` files elsewhere remain ignored.

## Scan scope

The default scan (`python3 tools/secret_scan.py`) excludes this directory so
that a clean result for the repository is meaningful. The exclusion notice is
printed for any scan root whose traversal would cover the fixture corpus
(e.g. the repository root or `--root tests`); scanning a narrower root such
as `templates/` prints no notice because nothing was excluded. The corpus
is validated by `--self-test`. Both commands must pass before any commit or
publication step, per GOVERNANCE.md.
