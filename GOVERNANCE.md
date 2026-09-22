# Governance

Changes are reviewed through pull requests. Security-sensitive changes should
include tests for failure paths, redaction, and fail-closed behavior.

Release artifacts must be built from a clean checkout with pinned dependencies.
Every release bundle includes checksums, an SBOM, and provenance metadata. CI
may build and publish artifacts, but it must not contain deployment credentials
or activate services on remote hosts.

Repository history, release tags, and published artifacts are immutable. If a
security issue requires replacement, publish a new commit and release with a
clear advisory instead of silently replacing existing artifacts.
