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
publication anchor at `.managed-profile` selects the authoritative directory
by a hard link to its immutable `.authority` file. The authority binds the
store and file identities through an extended attribute on macOS and Linux
or user-scoped DPAPI on Windows. The CLI refuses a missing or damaged selected
configuration. A readable original v1 `config.json` can disqualify a
publication when it reserves a publication path as a Token. Older layouts
without the platform proof require manual recovery from verified metadata
before migration. File copies and restored stores with different filesystem
identities also require recovery from verified metadata.
The CLI can migrate the original v1 `config.json`.
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

Unified, current Bot and Mail credential writes share `.managed.lock`. They
protect referenced Token paths and aliases from conflicting writes. Mail
checks its local storage and tests temp-file creation before starting or
exchanging a device code. On Windows it also checks existing destinations
for delete access, exclusive sharing and the read-only attribute. Writes
recheck destination ownership under the lock. Mail and Bot reads leave a
missing encryption salt alone. The encrypted-file backend leaves an external
`master.key` alone and excludes known external Token files from its scan for
existing ciphertext. On macOS, Keychain creation and
cleanup also protect locator files. Cleanup leaves an obsolete Keychain item
in place when a profile still uses its locator path as an external Token.
When the encrypted-file backend cannot use the system Keychain, it stores
the plaintext `master.key` alongside the ciphertext under `credentials/`.
A whole-directory backup, sync or accidental commit can expose both and
allow offline decryption.

When migrating directly from the original v1 configuration, the CLI verifies
the source inode and bytes, archives them as `config.v1-*.bak`, and publishes
the new configuration together with the recovery marker. On Windows, the
final publication uses a non-replacing, write-through move of the prepared
anchor. Once the publication is durable, the CLI clears the verified v1 file
into an empty Bot store.
A legacy writer that replaces `config.json` keeps its active file. Recovery
requires a retirement record published with the profile metadata, a matching
active inode, and the recorded backup digest. A retry after interrupted
staging also requires a matching staging anchor and the migration record
persisted before the hard link was created. Detached
markers and files without a published retirement record remain in place,
including files whose Token reference was previously removed. An older
migration interrupted without a record may require manual recovery before
using the Bot CLI.

**Trust boundary: the OS user account.** Any process running as the same user
can run `octo-cli` and therefore decrypt the store. Keychain-backed storage
protects an off-machine copy of the CLI directory when the Keychain data stays
on the source machine. The legacy Bot store's machine-bound key protects an
off-machine copy when the source machine ID is unavailable to its recipient.
Isolate mutually-distrusting bots with separate OS users or separate
`OCTO_CONFIG_DIR` values. The CLI's anti-misuse guards (ambiguous selection is a
hard error, `--bot-id` assertion, `identity` echoed on every response) prevent
*accidental* wrong-identity use, not a malicious same-user process.
