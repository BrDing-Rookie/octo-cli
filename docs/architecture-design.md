# Octo CLI framework architecture

`octo-cli` builds its service command tree from OpenAPI 3.x metadata at startup.
The default build contains the framework commands and an empty service registry.

```text
OpenAPI JSON -> Registry -> Cobra commands
                                 |
                        Factory and command runner
                                 |
                    HTTP client -> output formatter
```

| Component | Responsibility |
|---|---|
| `cmd/octo-cli` | Process entry point, signal handling, and exit status |
| `cmd` | Root flags, configuration, credential profiles, raw API calls, discovery, and distribution commands |
| `internal/registry` | Embedded specifications, operation discovery, and schema extraction |
| `cmd/service` | Command generation, argument validation, request building, and pagination |
| `internal/cmdutil` | Per-invocation configuration, credentials, transport, and output |
| `internal/client` | HTTP, authentication headers, retries, request previews, and diagnostics |
| `internal/output` | Response normalization, output formats, and error envelopes |

## Specification metadata

Store each specification as JSON in `internal/registry/specs`. Its
`operationId` supplies the command words. A specification owns each HTTP
method, path, and parameter schema. Generated requests use the configured
gateway origin and the path supplied by the specification.

Optional extensions configure shared engine features:

- `x-octo-service` and `x-octo-disabled` control service naming and discovery.
- `x-octo-cli-hidden` omits individual operations.
- `x-octo-flag` names a CLI flag. `x-octo-positional` can promote a required
  string query parameter to a positional argument.
- `x-octo-pagination` declares cursor and response field paths.
- `x-octo-multipart` and `x-octo-binary-response` describe file transport.
- `x-octo-secret` supplies redaction metadata.
- `x-octo-response-fields`, `x-octo-lossless-id-fields`, and
  `x-octo-response-unwrap` configure output normalization.
- `x-octo-strict-request-schema` and `x-octo-strict-response-schema` enable
  additional contract checks.
- `x-octo-retry` and `x-octo-auto-idempotency-key` describe retry and
  request-key behavior.

The generated commands validate their arguments before sending requests.
Optional `--data` inputs merge with explicit body flags. The raw `api`
command accepts a method and path directly and uses matching specifications
to identify sensitive values in diagnostics.

## Verification

Framework tests use synthetic OpenAPI specs outside the production registry.
The HTTP tests use local servers. Run `make test` to execute the Go suite
with the race detector and `npm --prefix npm test` to verify the distribution
launcher and package-manager behavior.
