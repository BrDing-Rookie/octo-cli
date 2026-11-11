# CLAUDE.md — octo-cli project instructions

## Project

`octo-cli` is a Go and Cobra framework for HTTP commands generated from
OpenAPI 3.x specifications. The default build ships with an empty registry.

- `cmd` wires the command tree, shared flags, and framework commands.
- `cmd/service` generates commands and executes operations from metadata.
- `internal/registry` embeds and loads JSON specifications.
- `internal/cmdutil` resolves dependencies per invocation.
- `internal/client` and `internal/output` handle transport and output.
- `npm` packages and launches the platform binary.

See [docs/architecture-design.md](docs/architecture-design.md) for the
framework contract. Keep service definitions under `internal/registry/specs`
and use synthetic specifications for framework tests.

## Code Style

- `gofmt`, `go vet`, standard-library `testing` with table-driven tests.
- Errors wrap with `fmt.Errorf("context: %w", err)`; CLI errors use the `*output.ExitError` taxonomy so envelopes stay structured.
- The `internal/output` package is a leaf — it must not import other `internal/*` packages.
- No mutable package-level globals; state flows through the Factory. The only package-level `var` declarations allowed are (a) ldflags-injected build metadata (`cmd/build.go`), (b) `//go:embed` file systems (`internal/registry`), and (c) immutable lookup tables (e.g. `backendErrorMapping` in `internal/output/errors.go`, `httpMethods` in `internal/registry/loader.go`). These are const-equivalent — never mutated at runtime — and exist only because Go doesn't permit `const` for their types.
- External deps limited to cobra, gojq, `golang.org/x/term` (hidden token prompt in `octo-cli auth login`), and the standard library.
- All text in English.

## Test Discipline

A test that passes is not evidence until it has failed. Write the assertion first,
run it against the unfixed code, and require it to fail **for the reason you
predicted** before writing the fix. If it passes before the fix, or fails for a
different reason, the assertion is wrong — fix the assertion, not the schedule.

This is not a preference. Assertions written after the code is already correct pass
whether or not they check anything, and this repo has produced several: a
`strings.EqualFold` comparison that ignored the case difference it existed to catch;
a chmod-target check satisfied by a `SameFile` guard three lines earlier; a
post-publication identity check satisfied by the pre-publication one. Each was found
later by mutation, which only tells you a test is weak once the bug is gone.

- **Predict the failure text**, then check the run matches it. "It failed" is not
  the bar; "it failed because the resolved address was never inspected" is.
- **Isolate the primitive.** If the property is about function X, call X directly.
  A path that reaches X through three earlier guards tests the earliest one.
- **Never assert on a substring you did not copy from the code.** Two of the above
  were checks for text nothing emits.
- **Mutation is the audit, not the proof.** Break the fix, confirm the test goes red,
  restore from a per-file `cp` backup — not `git checkout`, which silently does
  nothing for untracked files and takes unrelated edits with it when it does work.

Security boundaries additionally need a test in each direction: the unsafe input is
refused *and* the legitimate one still works. A guard with only the first half gets
widened by the next person who trips over it.

## Build & Test

```bash
go build -o octo-cli ./cmd/octo-cli
go test ./... -count=1
go vet ./...

# Shell completion (cobra built-in)
octo-cli completion bash   > /etc/bash_completion.d/octo-cli
octo-cli completion zsh    > "${fpath[1]}/_octo-cli"
octo-cli completion fish   > ~/.config/fish/completions/octo-cli.fish
```

Version metadata is injected via `-ldflags` at release time (see `cmd/build.go`).
