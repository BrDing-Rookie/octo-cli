# OpenAPI specifications

Place OpenAPI 3.x JSON files in this directory and rebuild to register service
commands. Each filename selects the service name unless the spec declares
`x-octo-service`.

`server.json` is derived from the [Octo Server v2 OpenAPI on the test branch](https://codex.mlamp.cn/dmwork/octo-server/-/blob/6ea222952bf1b8798f5e8c7bd10409af751fe8a9/docs/openapi/v2.yaml).
The CLI paths include the gateway's `/api` mount. The spec retains the
upstream operation IDs, parameters and schemas. CLI metadata selects
Token-derived Space, response envelopes, multipart uploads, and download
redirect handling. Mutations and credential issuance disable automatic
retries when a request outcome is uncertain. The spec marks storage
credentials and signed URLs for diagnostic redaction.
