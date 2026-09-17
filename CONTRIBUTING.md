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
hostnames, or deployment-specific addresses.

Security issues should be reported privately as described in
[SECURITY.md](SECURITY.md).
