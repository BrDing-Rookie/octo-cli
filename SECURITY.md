# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| main (latest) | ✅ |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by emailing the maintainers directly. Include:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix or mitigation plan within 7 days.

## Scope

This policy covers:
- Authentication bypass or token forgery
- Authorization flaws (cross-space data access)
- SQL injection or data exposure
- Denial of service via resource exhaustion
- Sensitive data in logs or error responses

## Token Handling

`octo-cli auth login` reads the Bearer from stdin (`--with-token`) or a file
(`--token-file`). Terminal input is hidden. Login imports the credential locally.
The business gateway authenticates the Bearer when a command sends a request.
`auth login` and `config show` report non-secret fields, and the CLI masks the
Bearer in request previews and diagnostics.

## Credential Storage

The CLI stores profile metadata in `~/.octo/cli/config.json`, with
`OCTO_CONFIG_DIR` available as an override. Managed credentials use the system
credential store. When that backend is unavailable, the CLI stores each Token
in an AES-256-GCM file with a random nonce and keeps a random master key in the
same private configuration directory.

The OS user account controls access to the managed store. A process that can
read both the master key and the encrypted credential can recover the Token.
`auth logout` removes the profile and cleans up its managed credential when
the last reference is removed. A `token_file` source points to a file managed
by its caller.
