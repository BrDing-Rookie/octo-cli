# Octo CLI MCP integration

`octo-cli mcp serve --listen` runs a service that clients on other machines
reach over Streamable HTTP. The client connects to `/mcp` and sends its existing
Octo CLI Token as a Bearer. The server uses that Token for the current `exec`
call to the configured Octo gateway. The gateway determines the caller's
identity and permissions.

## Enterprise deployment

The enterprise deployment runs through GitLab CI and Argo CD. Configure the
HTTPS gateway, release environments and Pod autoscaling in the
[CI deployment guide](../ci/mcp/README.md).

## Run a local HTTP test service

Build a binary with the `--listen` flag.

```sh
make build
./bin/octo-cli mcp serve --help
```

Point `OCTO_API_BASE_URL` at the Octo gateway origin.

```sh
OCTO_API_BASE_URL=https://octo-gateway.example.com \
  ./bin/octo-cli mcp serve --listen 127.0.0.1:8765
```

The production HTTPS gateway routes `https://octo-mcp.example.com/mcp` to the
MCP Service. Preserve the
`Authorization`, `Content-Type`, `Accept`, and `MCP-Protocol-Version` headers
and the request body. Keep the MCP service within the Octo gateway's trust
boundary. Configure access logs to omit `Authorization`.

A server-side `--profile` or `OCTO_PROFILE` constrains the gateway and Space.
The Bearer for HTTP commands comes from each client's request.

## Connect an external client

Use a client that supports Streamable HTTP with a Bearer header. Give it the
public `/mcp` URL. For each request it sends `Authorization: Bearer <octo-token>`
with the existing Octo Token for the intended environment. The service checks
the header format. The gateway authenticates the Token on business requests.
[Streamable HTTP transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#streamable-http)

### Codex

In the client environment, set `OCTO_TOKEN` to the caller's Octo Token. Add
the following entry to `~/.codex/config.toml` on the Codex host. Restart the
MCP connection and use `/mcp` to check that `octo` is active.
[Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)

```toml
[mcp_servers.octo]
url = "https://octo-mcp.example.com/mcp"
bearer_token_env_var = "OCTO_TOKEN"
```

### Verify over HTTP

Set `OCTO_TOKEN` in the environment of the machine running these commands.
Replace the example URL with the service URL. Send `initialize` and use the
returned `result.protocolVersion` for `octo_mcp_version`. Initialization with
this example requests `2025-11-25`. The notification receives HTTP `202` with
an empty body. The last request checks a business call on a build with Octo
Server v2 and a Token with `im.identity:read`.

```sh
octo_mcp_url='https://octo-mcp.example.com/mcp'

octo_mcp_post() {
  printf 'Authorization: Bearer %s\n' "${OCTO_TOKEN:?set OCTO_TOKEN}" |
    curl -fsS "$octo_mcp_url" --header @- \
      --header 'Content-Type: application/json' \
      --header 'Accept: application/json, text/event-stream' "$@"
}

octo_mcp_post --data-binary \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'

octo_mcp_version='2025-11-25'

octo_mcp_post --header "MCP-Protocol-Version: $octo_mcp_version" \
  --data-binary '{"jsonrpc":"2.0","method":"notifications/initialized"}'

octo_mcp_post --header "MCP-Protocol-Version: $octo_mcp_version" \
  --data-binary '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

octo_mcp_post --header "MCP-Protocol-Version: $octo_mcp_version" \
  --data-binary '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exec","arguments":{"args":["server","identity","get","--jq",".data.user_id"]}}}'
```

The HTTP endpoint returns one JSON-RPC response per request ID and uses
`2025-03-26`, `2025-06-18`, or `2025-11-25`. Authenticate each POST.

## Call the tool

`exec` accepts an `args` array of 1 to 256 strings. Pass each argument after
`octo-cli` as a separate element. Spaces inside an argument are preserved. NUL
characters and unknown or duplicate JSON fields in the tool arguments are
rejected. Use schema discovery to see the operations bundled into the server
binary. Over HTTP, business calls use registered service commands and their
CLI validators. The raw `api` command is available in the CLI and local stdio.

```json
{"args":["schema","--list"]}
```

Inspect the resolved gateway and credential source with `config show`. The
credential source for HTTP is `mcp:authorization`.

```json
{"args":["config","show"]}
```

For an Octo Server v2 build, use `--dry-run` to preview the identity request.
The preview runs locally. Use the authenticated identity request above to
verify gateway access.

```json
{"args":["server","identity","get","--dry-run"]}
```

Supply inline JSON as a single argument to `--data`.

```json
{"args":["server","message","search-global-groups","--data","{\"keyword\":\"example\"}","--dry-run"]}
```

For HTTP calls, `--timeout` takes a positive Go duration such as `10s`,
`--page-limit` takes an integer from 1 to 100 with `--page-all`, and `--jq`
accepts direct field and array index selectors such as `.data.items[0].id`.
Query parameters and request bodies are checked against the registered CLI
schema, including declared numeric bounds.

A successful identity lookup for `fixture-user` with the `--jq` filter in
the HTTP example includes the following fields.

```json
{
  "structuredContent": {
    "stdout": "\"fixture-user\"\n",
    "stderr": "",
    "exitCode": 0
  },
  "isError": false
}
```

`exitCode` and `isError` report command status. `stdout` contains the selected
CLI output and `stderr` contains traces or the CLI error envelope. The CLI
fields are also available as JSON text in `content[0].text`. Protocol versions
`2025-06-18` and `2025-11-25` include `structuredContent`.

Run local file operations, credential management, and upgrades directly with
the CLI.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| HTTP `401` at `/mcp` | Send the Octo Token in the `Authorization: Bearer …` header and confirm the proxy forwards it. |
| HTTP `403` at `/mcp` for a browser request | Use a native MCP client or call through your application's backend. |
| `isError` with `auth_error` in the tool result | Check the Token's validity for the configured Octo gateway. |
| `PROFILE_SCOPE_MISMATCH` | Match any gateway or Space override to the profile configured on the server. |
| An identity call returns a gateway permission error | Check that the Token has `im.identity:read` in the intended Space. |
| `tools/call` returns JSON-RPC error `-32602` | Use the tool name `exec` and pass 1 to 256 strings in `arguments.args`. |
| A Server v2 command is missing | Use `schema --list` and check that the deployed binary bundles the Server v2 registry. |

## Local stdio clients

To let a local client launch its own server process, use `mcp serve` as the
launch arguments. In this mode the process uses the standard CLI credential
resolution, including `OCTO_TOKEN_FILE`, `OCTO_TOKEN`, or a saved profile.
Close the process's stdin to end its MCP session.
[Octo CLI credentials and profiles](../README.md#configuration-and-credentials)

```toml
[mcp_servers.octo_local]
command = "/absolute/path/to/octo-cli"
args = ["mcp", "serve"]

[mcp_servers.octo_local.env]
OCTO_TOKEN_FILE = "/absolute/path/to/octo.token"
OCTO_API_BASE_URL = "https://octo-gateway.example.com"
```
