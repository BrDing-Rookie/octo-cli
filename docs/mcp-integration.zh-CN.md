# Octo CLI MCP 对外接入指南

`octo-cli mcp serve --listen` 将 Octo CLI 运行成常驻服务。外部客户端通过
Streamable HTTP 连接 `/mcp`，在请求头里传入自己已有的 Octo CLI Token。服务将
该 Token 用于本次 `exec` 调用，由配置好的 Octo 网关校验调用方身份和业务权限。

## 企业部署

企业环境通过 GitLab CI 构建镜像并触发 Argo CD 发布。HTTPS 网关、发布环境和 Pod
扩缩容参数见 [CI 部署指南](../ci/mcp/README.md)。

## 启动本地 HTTP 测试服务

构建支持 `--listen` 的二进制。

```sh
make build
./bin/octo-cli mcp serve --help
```

将 `OCTO_API_BASE_URL` 设置为 Octo 网关的源地址。

```sh
OCTO_API_BASE_URL=https://octo-gateway.example.com \
  ./bin/octo-cli mcp serve --listen 127.0.0.1:8765
```

生产 HTTPS 网关将 `https://octo-mcp.example.com/mcp` 转发到 MCP Service。保留
请求体及 `Authorization`、`Content-Type`、
`Accept` 和 `MCP-Protocol-Version` 请求头。将 MCP 服务部署在 Octo 网关的信任
边界内，访问日志应省略 `Authorization`。

服务端如果设置了 `--profile` 或 `OCTO_PROFILE`，该 Profile 会约束网关和 Space。
HTTP 命令使用各自请求头中的 Bearer。

## 外部客户端接入

选择支持 Streamable HTTP 且能配置 Bearer 请求头的 MCP 客户端。填入服务对外的
`/mcp` URL，在每次请求中发送 `Authorization: Bearer <octo-token>`。这里填写
调用方在目标环境已有的 Octo Token。入口检查请求头格式，Octo 网关在业务请求时
校验 Token。
[Streamable HTTP 传输规范](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#streamable-http)

### Codex

在运行 Codex 的环境中设置 `OCTO_TOKEN`，值为调用方已有的 Octo Token。在该主机
的 `~/.codex/config.toml` 中添加以下配置。重新连接 MCP 后，用 `/mcp` 确认
`octo` 已连接。
[Codex MCP 配置](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)

```toml
[mcp_servers.octo]
url = "https://octo-mcp.example.com/mcp"
bearer_token_env_var = "OCTO_TOKEN"
```

### 用 HTTP 验证接入

在执行下面命令的机器上先设置 `OCTO_TOKEN`，再把 URL 替换成服务地址。发送
`initialize` 后，将返回的 `result.protocolVersion` 填入 `octo_mcp_version`，
本例请求 `2025-11-25`。初始化通知返回 HTTP `202`，响应体为空。最后一条请求
执行身份查询，需要服务包含 Octo Server v2，并且 Token 具备 `im.identity:read`。

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

HTTP 入口为每条带 `id` 的请求返回一条 JSON-RPC 响应，支持 `2025-03-26`、`2025-06-18`
和 `2025-11-25`。每次 POST 都携带 Bearer 请求头。

## 调用工具和读取结果

`exec` 工具接收含 1 到 256 个字符串的 `args` 数组。每个元素对应 `octo-cli`
后面的一个参数，保留参数值里的空格。工具参数中的 NUL 字符、未知 JSON 字段和
重复 JSON 字段都会被拒绝。用 schema 查询查看服务二进制中内置的操作。HTTP
业务调用使用已注册的服务命令，并走对应的 CLI 校验。原始 `api` 命令可通过 CLI
或本地 stdio 调用。

```json
{"args":["schema","--list"]}
```

用 `config show` 查看网关和凭据来源。HTTP 请求的来源显示为 `mcp:authorization`。

```json
{"args":["config","show"]}
```

如果服务包含 Octo Server v2，可用 `--dry-run` 在本地预览身份查询，再用上面的
实际身份查询确认网关访问。

```json
{"args":["server","identity","get","--dry-run"]}
```

给 `--data` 提供内联 JSON，将完整请求体放进一个数组元素。

```json
{"args":["server","message","search-global-groups","--data","{\"keyword\":\"example\"}","--dry-run"]}
```

HTTP 调用中的 `--timeout` 接受正时长，例如 `10s`。`--page-limit` 需要与
`--page-all` 一起使用，范围为 1 到 100。`--jq` 支持直接取字段或数组下标，
例如 `.data.items[0].id`。查询参数和请求体按已注册的 CLI schema 校验，包含
schema 声明的数值范围。

用 HTTP 示例中的 `--jq` 查询到用户 `fixture-user` 时，MCP 结果包含以下字段。

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

`exitCode` 和 `isError` 表示命令状态。`stdout` 是 CLI 按所选格式生成的输出，
`stderr` 包含跟踪信息或 CLI 错误响应。三个 CLI 字段也会以 JSON 文本放在
`content[0].text` 中。使用 `2025-06-18` 或 `2025-11-25` 时，结果还包含
`structuredContent`。

本地文件操作、凭据管理和二进制升级请直接使用 CLI。

## 常见问题

| 现象 | 检查项 |
| --- | --- |
| `/mcp` 返回 HTTP `401` | 检查 `Authorization: Bearer …` 请求头，并确认代理透传了它。 |
| 浏览器请求 `/mcp` 返回 HTTP `403` | 使用原生 MCP 客户端，或由应用的后端调用。 |
| 工具结果显示 `isError`，且包含 `auth_error` | 检查 Token 对配置的 Octo 网关是否有效。 |
| 返回 `PROFILE_SCOPE_MISMATCH` | 显式指定的网关或 Space 要与服务端 Profile 的绑定一致。 |
| 身份查询返回网关权限错误 | 检查 Token 在目标 Space 中是否有 `im.identity:read`。 |
| `tools/call` 返回 JSON-RPC 错误 `-32602` | 确认工具名为 `exec`，并在 `arguments.args` 中传入 1 到 256 个字符串。 |
| 查不到 Server v2 命令 | 用 `schema --list` 检查部署的二进制是否内置 Server v2 注册表。 |

## 本地 stdio 接入

本机客户端也可用 `mcp serve` 启动自己的 MCP 进程。该模式按 CLI 规则解析
`OCTO_TOKEN_FILE`、`OCTO_TOKEN` 或已保存的 Profile。关闭进程的 stdin 即可
结束 MCP 会话。
[Octo CLI 凭据与 Profile](../README.md#configuration-and-credentials)

```toml
[mcp_servers.octo_local]
command = "/absolute/path/to/octo-cli"
args = ["mcp", "serve"]

[mcp_servers.octo_local.env]
OCTO_TOKEN_FILE = "/absolute/path/to/octo.token"
OCTO_API_BASE_URL = "https://octo-gateway.example.com"
```
