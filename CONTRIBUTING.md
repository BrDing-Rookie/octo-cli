# Contributing to octo-cli

Thanks for your interest in improving `octo-cli`. This document covers what you
need to know to get a change merged.

## Prerequisites

- Go **1.24+** (see [`go.mod`](./go.mod))
- `make` (optional — targets are plain shell)
- `golangci-lint` for local lint runs (CI enforces the same config)

## Quick Start

```bash
git clone https://github.com/Mininglamp-OSS/octo-cli.git
cd octo-cli

make hooks            # install git hooks (lefthook) — do this once
make build            # builds ./bin/octo-cli
make test             # go test -race -count=1 ./...
make lint             # golangci-lint run
make ci               # fmt + vet + lint + test + build (what CI runs)
```

## Git Hooks

Hooks are managed by [lefthook](https://lefthook.dev) and mirror the CI checks
so problems surface locally instead of on the remote. Activate them once after
cloning with `make hooks` (installs into `.git/hooks/`); the config lives in
[`lefthook.yml`](./lefthook.yml).

| Hook | Runs | Notes |
|------|------|-------|
| `pre-commit` | `gofmt` (staged files) + `go vet` + `golangci-lint` | Fast. `golangci-lint` is skipped with a hint if not installed — CI still enforces it. |
| `commit-msg` | Conventional Commits check | See [`.lefthook/commit-msg-check.sh`](./.lefthook/commit-msg-check.sh). |
| `pre-push` | `go mod tidy` drift check + `go build ./...` + `go vet ./...` | Fast gate. The full `go test -race -shuffle` + coverage suite runs in CI, not on every push. |

`lefthook` is the only extra tool required — install it with `brew install lefthook`
or `go install github.com/evilmartians/lefthook@latest`. Optional linters used by
the hooks and CI install via `make tools` (`golangci-lint`, `gci`).

> Hooks can be bypassed with `--no-verify` (`git commit --no-verify`,
> `git push --no-verify`) **in genuine emergencies only** — CI runs the same
> checks, so a bypass just defers the failure.

## Architecture and service specifications

The [architecture guide](docs/architecture-design.md) describes the framework
and metadata extensions. The built-in service registry starts empty.

1. Write an OpenAPI 3.x JSON specification in `internal/registry/specs`.
2. Rebuild with `make build`. Check the generated commands with `--help` and
   `schema --list`.
3. Use synthetic specs and local HTTP servers for framework regression tests.
   Verify a service's API contract separately.

## Code Style

- `gofmt` — run `gofmt -s -w .` before pushing.
- `go vet ./...` — must pass.
- `golangci-lint run` — CI uses `.golangci.yml`; keep it green.
- Errors wrap with `fmt.Errorf("context: %w", err)`. User-facing errors
  should be `*output.ExitError` so envelopes stay structured.
- External dependencies are limited to `cobra`, `gojq`, and the standard
  library.
- Only add comments for non-obvious *why* — avoid narrating *what* the code
  does when the names already carry that.

## Testing

- `go test -race -count=1 ./...` must pass locally before you open a PR.
- Every behavior change ships with a test. Table-driven tests preferred.
- Use Factory stubs (`ConfigFunc`, `CredentialFunc`, `ClientFunc`,
  `RegistryFunc`) — don't touch real environment or network in tests.

## Pull Request Process

1. Fork and create a topic branch from `main`.
2. Keep the change focused; split unrelated work into separate PRs.
3. Fill in the PR template. Link the issue.
4. Use **Conventional Commits** for commit messages and PR titles:
   - `feat: add cursor validation`
   - `fix: preserve ExitCode through retry exhaustion`
   - `docs: rewrite README`
   - `refactor: split service.go into four files`
   - `test: cover multipart edge cases`
   - `chore: bump golangci-lint to v1.61`
5. CI must be green: gofmt, vet, golangci-lint, `go test -race`, build,
   `go mod tidy` check.

## Reporting Security Issues

See [SECURITY.md](./SECURITY.md). Please do not file security issues in the
public tracker.

## License

By contributing you agree that your contribution will be licensed under the
project's [Apache-2.0 license](./LICENSE).
