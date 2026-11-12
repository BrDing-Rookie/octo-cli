---
name: octo-shared
description: Inspect the Octo CLI framework, select credentials, preview HTTP requests, and consume structured results.
---

# octo-shared

Use `octo-cli schema --list` to discover embedded operations. Inspect an operation
with `octo-cli schema <operation-id>`. This framework build starts with an empty
service registry.

Select a profile with `--profile` or `OCTO_PROFILE`. For an external Bearer,
use `--credential-file`, `OCTO_TOKEN`, or `OCTO_TOKEN_FILE`. Set only one Token
environment variable. Without an explicit profile, external credentials use
`OCTO_API_BASE_URL` and the runtime Space. Use `octo-cli auth login` to import a
Token locally and `octo-cli auth logout` to remove a profile. Use
`octo-cli config show` for the resolved target and credential source.

Use `octo-cli api <METHOD> <PATH>` for a direct request to the configured
gateway. `--params` accepts a JSON object and `--data` accepts inline JSON,
`@file`, or `@-` for stdin. Preview the request with `--dry-run` before sending it.

Success uses stdout and defaults to a JSON envelope. Errors use stderr and
a nonzero exit status. Use `--jq` to select fields from the success envelope.
