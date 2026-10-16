# Contributing

Contributions are welcome through pull requests.

Before submitting a change, run:

```sh
gofmt -w ./cmd ./internal
go test ./...
go vet ./...
python3 -m unittest discover -s tests -p 'test_*.py'
python3 tools/secret_scan.py --self-test
python3 tools/secret_scan.py
```

Keep changes focused and include tests for new behavior. Configuration examples
must contain placeholders only; never commit credentials, private keys, live
hostnames, deployment-specific addresses, operator infrastructure, task
background, or private usage scenarios. Use reserved documentation domains and
address ranges in examples. Experimental results may be published under
`docs/experiments/` after removing operator identities, real endpoints, user
activity, exact operational timestamps, and private configuration. Preserve
failed attempts, measurement definitions, and limitations in the public result
set. Raw operator evidence remains local. Run
`python3 tools/verify_experiment_results.py` before submitting result changes.

Security issues should be reported privately as described in
[SECURITY.md](SECURITY.md).
