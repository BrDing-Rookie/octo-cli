# octo-cli

[![CI](https://github.com/Mininglamp-OSS/octo-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/Mininglamp-OSS/octo-cli/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Mininglamp-OSS/octo-cli.svg)](https://pkg.go.dev/github.com/Mininglamp-OSS/octo-cli)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

`octo-cli` is an OpenAPI-driven command-line framework for HTTP APIs. It
builds a single Go binary with an extensible Cobra command tree, credential
profiles, request previews and structured output for scripts and agents.

This checkout ships with an empty service registry. The framework commands are
`api`, `schema`, `auth`, `config`, `skills`, `upgrade`, `version`, `help` and
`completion`.

## Build and try the framework

```sh
make build
./bin/octo-cli --help
./bin/octo-cli schema --list
```

`schema --list` starts with empty `services` and `operations` arrays. To preview
a request through the generic HTTP command, use a fixture origin and token:

```sh
OCTO_API_BASE_URL=https://api.example.invalid OCTO_TOKEN=fixture_token \
  ./bin/octo-cli api GET /v1/items --params '{"limit":10}' --dry-run
```

`api <METHOD> <PATH>` accepts JSON query parameters through `--params` and a
JSON body through `--data`. Use `--data @file.json` or `--data @-` to read a
body from a file or stdin. Paths are relative to the configured gateway.

## Configuration and credentials

For `api` and generated commands, the CLI reads the Bearer from
`--credential-file`, then `OCTO_TOKEN` or `OCTO_TOKEN_FILE`, then the selected
profile. Set only one Token environment variable. Profiles are selected by
`--profile`, `OCTO_PROFILE`, or the saved `current_profile`. An external
credential without an explicit profile uses `OCTO_API_BASE_URL` and the runtime
Space from `--space` or `OCTO_SPACE_ID`.

The CLI stores version 1 profiles in `~/.octo/cli/config.json`. Set
`OCTO_CONFIG_DIR` to use a dedicated private directory. A managed profile
binds the credential to its saved gateway origin and Space. Reimport to change
that binding.

Set `OCTO_AUTH_CURRENT_URL` to the full Token verification URL for the target
environment. Pipe the Token into `auth login --with-token` or import it from
a file with `--token-file`.

```sh
octo-cli --profile agent --space "$space_id" auth login \
  --api-base-url "$api_origin" --with-token < "$token_file"
octo-cli --profile agent auth status
```

A successful import selects the profile as `current_profile`. Managed credentials
use the system credential store when available or a private AES-256-GCM file
with a random master key. `auth status` checks a managed profile offline and
returns `ready` or `missing`. `auth list` and `config show` display non-secret
metadata. `auth logout` removes the profile and cleans its unreferenced
managed entry.

## Add an OpenAPI specification

Place an OpenAPI 3.x JSON file in [internal/registry/specs](internal/registry/specs)
and rebuild. The filename selects the service name unless the spec declares
`x-octo-service`. An operation such as `example.item.get` becomes
`octo-cli example item get`. Path parameters become positional arguments.
Query and header parameters and simple body properties become flags.

Use `schema --list` and `schema <operation-id>` to inspect the resulting
registry. See the [architecture guide](docs/architecture-design.md) for the
request flow and supported metadata. `octo-cli skills octo-shared` prints
the bundled framework guidance.

Successful commands default to a JSON envelope on stdout. Errors use a
structured envelope on stderr and a nonzero exit code. `--jq` filters the
success envelope and `--format` selects `json`, `table`, `csv`, or `ndjson`.
Use `--dry-run` to preview a request, `--verbose` for diagnostics, and
`--timeout` or `--no-retry` to control transport.

## Distribution

### npm, Bun or pnpm

For Node-based agent runtimes (OpenClaw, etc.):

```bash
npm install -g @mininglamp-oss/octo-cli

# Or use the global package manager for your runtime:
bun install -g @mininglamp-oss/octo-cli
pnpm add -g @mininglamp-oss/octo-cli
```

The npm package resolves the matching platform sub-package, which already
contains the prebuilt binary. Install does not download binaries from GitHub.

### Go install

```bash
go install github.com/Mininglamp-OSS/octo-cli/cmd/octo-cli@latest
```

### GitHub Releases

Download the latest binary for your platform from
[GitHub Releases](https://github.com/Mininglamp-OSS/octo-cli/releases):

```bash
# Archives are named octo-cli_<version>_<os>_<arch>.tar.gz for every platform,
# including Windows. Pick the one for your platform and substitute <version>
# (e.g. 0.5.0):
curl -LO https://github.com/Mininglamp-OSS/octo-cli/releases/download/v<version>/octo-cli_<version>_linux_amd64.tar.gz
tar xzf octo-cli_<version>_linux_amd64.tar.gz
sudo mv octo-cli /usr/local/bin/
```

Windows release archives are `.tar.gz` as well; Windows 10+ includes `tar.exe`.

### install.sh

```bash
curl -fsSL https://raw.githubusercontent.com/Mininglamp-OSS/octo-cli/main/install.sh | sh
```

### Upgrade a global package installation

```bash
octo-cli upgrade --dry-run
octo-cli upgrade
```

`upgrade` identifies the npm, Bun or pnpm installation that owns the invoked
command and updates it to the configured registry's stable `latest` release.
An equal or newer installed version is a successful no-op. It verifies the
installed package, platform binary and command before reporting success.

Updates enable optional dependencies for npm/pnpm and explicitly install Bun's
matching platform package, because its executable is required to run the CLI.

Registry mirrors, scoped registries and authentication use the owning manager's
native settings: npm's user/global `.npmrc` and environment, Bun's supported
`.npmrc` and global `.bunfig.toml`, or pnpm's native configuration. The invoking
project's registry settings do not redirect the upgrade.

Dry run checks local ownership without contacting a registry or installing.
Upgrade requires no Octo credentials and preserves `--format` / `--jq`.
Use the original installation method for raw binaries, `go install`, project-local
or temporary installs. Package-manager
failures stop the command; an installation failure can leave partially changed
files, so inspect the structured error before retrying.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and verification.

## License

[Apache 2.0](LICENSE).

## Optional COS distribution

See [Optional COS publishing](docs/cos-publishing.md) for local release tools.
