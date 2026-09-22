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
background, private usage scenarios, or measured results from a private
environment. Use reserved documentation domains and address ranges in examples.

Security issues should be reported privately as described in
[SECURITY.md](SECURITY.md).
