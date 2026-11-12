---
name: octo-shared
description: Inspect the Octo CLI framework, select credentials, preview HTTP requests, and consume structured results.
---

# octo-shared

Use `octo-cli schema --list` to discover embedded operations. Inspect an operation
with `octo-cli schema <operation-id>`. This framework build starts with an empty
service registry.

Set `OCTO_TOKEN` for HTTP commands and use `OCTO_API_BASE_URL` to select
the gateway origin. Use `octo-cli auth status` or `octo-cli config show`
to inspect local bot profile settings.

Use `octo-cli api <METHOD> <PATH>` for a direct request to the configured
gateway. `--params` accepts a JSON object and `--data` accepts inline JSON,
`@file`, or `@-` for stdin. Preview the request with `--dry-run` before sending it.

Success uses stdout and defaults to a JSON envelope. Errors use stderr and
a nonzero exit status. Use `--jq` to select fields from the success envelope.
