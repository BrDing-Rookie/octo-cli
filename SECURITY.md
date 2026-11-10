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
metadata is unreadable. The CLI can migrate the original v1 `config.json`.
Before publication, unmarked dedicated metadata with profiles requires the
same bindings and default selection in the original v1 file. An empty
dedicated store still suppresses older profiles when the original is present.
Root archives can flag a potential Token conflict at `config.json` but cannot
authorize a configuration. If only unmarked dedicated metadata and root
archives remain, profile resolution stops until the original verified v1
metadata is restored. To migrate before running an older CLI, run
`auth update` in unified mode with the selected profile's existing
`--api-base-url`. Existing Token files stay at their paths,
including targets that are temporarily missing. Relative Token paths and
managed credential references keep their original base.

Unified and current Bot profile writes share `.managed.lock`. Both protect
referenced Token paths and aliases from conflicting writes. The encrypted-file
backend leaves an external `master.key` alone. On macOS, Keychain creation and
cleanup also protect locator files. Cleanup leaves an obsolete Keychain item
in place when a profile still uses its locator path as an external Token.

When migrating directly from the original v1 configuration, the CLI verifies
the source inode and bytes, archives them as `config.v1-*.bak`, and publishes
the new configuration together with the recovery marker. Once the publication
is durable, the CLI clears the verified v1 file into an empty Bot store.
A legacy writer that replaces `config.json` keeps its active file. Recovery
requires a matching active inode and a valid paired backup. A retry after
interrupted staging removes an old pin only when it still links to the
verified migration source and its backup matches the source bytes. Detached
markers and unmarked `config.json` files remain in place after publication,
including files whose Token reference was previously removed. An older migration that
left an unmarked v1 file may require manual recovery before using the Bot CLI.

**Trust boundary: the OS user account.** Any process running as the same user
can run `octo-cli` and therefore decrypt the store; the encryption defends against
off-machine leakage (accidental commit, backup, cloud sync), not a co-resident
process. Isolate mutually-distrusting bots with separate OS users or separate
`OCTO_CONFIG_DIR` values. The CLI's anti-misuse guards (ambiguous selection is a
hard error, `--bot-id` assertion, `identity` echoed on every response) prevent
*accidental* wrong-identity use, not a malicious same-user process.
