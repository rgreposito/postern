# Contributing

PRs welcome. A few ground rules, mostly so I do not have to repeat
them in review comments.

- Policy eval is fail-closed. If your change makes a missing grant
  succeed, it is a bug, not a feature.
- Do not add a dependency without a note in `docs/adr/`. The bar is
  "I can read the verifier in one screen".
- Tests for `internal/policy` and `internal/certs` are not optional.
- `go test -race ./...` should stay green.
- Do not widen a glob to make a test pass. Fix the matcher or the
  fixture.

I am slow on weekends. That is not a no.
