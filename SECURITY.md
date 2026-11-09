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

A bot token never appears on the command line. `octo-cli auth login` reads it from a
hidden, asterisk-masked terminal prompt, from stdin (`--with-token`), or from a
file (`--token-file`) — so it is never written to argv, shell history, or an
agent transcript.

Wherever a token surfaces in output (`auth status`, `config show`, `--dry-run`
Authorization header) it is masked. For a recognized kind the masking reveals
the prefix, two leading body chars, a fixed `***`, and the last four chars (so
two tokens are distinguishable without exposing the secret, and the middle is
fixed-width so token length is not leaked):

| Token | Displayed as |
|---|---|
| `app_<long body>` | `app_ab***5678` |
| `bf_<long body>` | `bf_so***hing` |
| `app_`/`bf_` with a short body | `app_***` / `bf_***` |
| Unrecognized prefix | `***` (reveal nothing) |
| Empty | `null` |

## Credential Storage

`octo-cli auth login` stores tokens encrypted on disk under `~/.octo-cli` (override
with `OCTO_CONFIG_DIR`):

- **`credentials.enc`** (0600) — tokens, AES-256-GCM with a random per-message
  nonce. **`config.json`** (non-secret profile metadata) and **`cred.salt`**
  (0600) live alongside; the directory is 0700.
- The encryption key is `SHA256(machineID ‖ salt)`. The machine id is read per
  OS (`/etc/machine-id` on Linux, `IOPlatformUUID` on macOS, `MachineGuid` on
  Windows; platforms without one fall back to salt-only). It is **not a secret**
  — the binding means a copied/synced/backed-up `~/.octo-cli` cannot be
  decrypted on a *different* machine, not that an attacker who has the file
  cannot eventually decrypt it given the same host.

Unified profiles are stored in **`profiles.json`** inside a private directory
allocated under the configured CLI directory (`~/.octo/cli` by default). A
publication marker identifies the authoritative directory, including when its
metadata is unreadable. The CLI can read the original v1 `config.json` and
earlier dedicated layouts, and publishes them on the next successful unified
profile write. To migrate before running an older CLI, run `auth update` in
unified mode with the selected profile's existing `--api-base-url`. Existing
Token files stay at their paths, including targets that are temporarily missing.
Relative Token paths and managed credential references keep their original base.

After the unified configuration is durable, the CLI archives the original v1
metadata as `config.v1-*.bak` before clearing the inspected v1 file into an
empty Bot store. A legacy writer that has already replaced `config.json`
keeps its active file. A pending marker pins the inspected file for recovery
after a partial write. A subsequent unified profile mutation resumes retirement
only if the active file still matches that marker. The backup retains the
original bytes for recovery.

**Trust boundary: the OS user account.** Any process running as the same user
can run `octo-cli` and therefore decrypt the store; the encryption defends against
off-machine leakage (accidental commit, backup, cloud sync), not a co-resident
process. Isolate mutually-distrusting bots with separate OS users or separate
`OCTO_CONFIG_DIR` values. The CLI's anti-misuse guards (ambiguous selection is a
hard error, `--bot-id` assertion, `identity` echoed on every response) prevent
*accidental* wrong-identity use, not a malicious same-user process.
