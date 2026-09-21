# Sandfox

Sandfox is a local-first desktop client for managing [sing-box](https://sing-box.sagernet.org) on macOS, Windows, and Linux. It gives users a graphical way to manage proxy profiles, routing policies, DNS, rule sets, runtime logs, diagnostics, and a compatible privileged service helper.

Sandfox is written in Go and Wails v3, with a React frontend. It is early software and preparing for its first public tagged release.

## Why Sandfox

sing-box is powerful, but users often have to edit JSON by hand, convert rules from other formats, understand route precedence, and manage privileged startup separately on each operating system. Sandfox focuses on that maintenance work:

- import and edit `sing-box`, Clash, or subscription-style profiles locally;
- manage proxy groups, custom groups, providers, routing policies, DNS policies, DNS servers, and rule sets;
- generate and preview `sing-box` configuration before starting the core;
- inspect runtime status, traffic, proxy groups, logs, and connection state;
- configure autostart, system proxy, and platform-specific privileged service workflows;
- keep a local-first data model with export, import, and configuration backup support.

Sandfox intentionally does not provide or bundle subscriptions or proxy servers.

## Status

- Target platforms: macOS 12+, Windows 10+ with WebView2, and current Linux distributions with GTK4 and WebKitGTK 6.
- Architectures: arm64 and amd64 are the primary release targets.
- Core dependency: a user-installed `sing-box` binary. Sandfox can detect it on `PATH` or use the path configured in Core settings.
- Verification state: the automated Rover parity audit currently covers 25 of 29 completion gates. The remaining gates require real target-host evidence for privileged service lifecycles and full Linux packaging.
- Release state: pre-release. Until the first tag is published, run from source or use artifacts built locally from a specific commit.

See [ROADMAP.md](ROADMAP.md) for priorities and [docs/rover-parity-audit.md](docs/rover-parity-audit.md) for the current evidence boundary.

## Features

### Profiles and subscriptions

- Import remote subscriptions, Clash, or `sing-box` profiles.
- Update profiles on a configurable interval and filter imported nodes.
- Manage nodes, proxy groups, custom groups, providers, health checks, latency tests, and policy overrides.
- Preserve subscription metadata and provider state without storing credentials in the repository.

### Routing and DNS

- Edit policies for domains, suffixes, keywords, CIDRs, ports, process names, protocols, query types, and other supported matchers.
- Import policy templates and preset rule sets.
- Configure DNS servers, DNS policies, detours, strategy, FakeIP, fallback filters, and hosts.
- Preview generated configuration and export a snapshot for review or troubleshooting.

### Runtime and diagnostics

- Start or stop the local `sing-box` process through the app or the compatible privileged helper.
- View API, mixed proxy, TUN, DNS, core, helper, and system-integration status.
- Read application and `sing-box` logs, clear logs, inspect connections, test proxy delay, and probe the Clash-compatible API.
- Run `sandfox --diagnose-core` to generate, validate, start, probe, and stop the configured core.

## Requirements

- Go 1.25 or newer
- Node.js and npm
- [Wails v3 CLI](https://v3.wails.io) installed as `wails3`
- `sing-box` on `PATH`, or configured in Core settings
- Platform packages and signing/notarization tools when building distributable packages

If Wails is installed in the default Go bin directory:

```sh
export PATH="$HOME/go/bin:$PATH"
```

## Development

```sh
wails3 dev
```

Build the current platform:

```sh
wails3 build
```

Run the core verification suite:

```sh
wails3 task verify
```

`verify` runs:

- `wails3 task parity:rover`
- `go test ./...`

The parity check reads a local Rover checkout from `/tmp/rover-source` by default. Override it with:

```sh
ROVER_SOURCE=/path/to/rover node scripts/rover-parity-check.mjs
```

Frontend type checking and production build are also useful for UI changes:

```sh
cd frontend
npm install
npm run build
```

Run the stricter completion audit:

```sh
wails3 task audit:rover
```

This command is expected to fail until environment-bound gates are verified on real macOS, Windows, and Linux hosts. It separates automated parity evidence from local package artifacts and target-host service evidence.

## Packaging

macOS:

```sh
wails3 task package
```

This creates `bin/sandfox.app` with ad-hoc signing.

Windows:

```sh
wails3 task windows:package
ARCH=amd64 wails3 task windows:package
```

The task writes `bin/sandfox.exe` and `bin/roverservice.exe`, then emits an installer such as `bin/sandfox-arm64-installer.exe` or `bin/sandfox-amd64-installer.exe`.

Linux:

```sh
wails3 task linux:package
```

This creates AppImage, DEB, RPM, and Arch packages. Linux cross-packaging uses Docker and the `wails-cross` image.

Platform signing and target-host validation are release-maintainer tasks. See [MAINTAINERS.md](MAINTAINERS.md) and [docs/target-validation-runbook.md](docs/target-validation-runbook.md).

## Project layout

- `main.go`: Wails application shell, window, tray, and diagnostics entry point.
- `service.go`: main Sandfox service, state, profile, policy, DNS, rule, and configuration-generation logic.
- `platform.go`: platform integration and privileged service management.
- `cmd/roverservice`: RoverService-compatible privileged helper.
- `frontend/`: React UI and generated Wails bindings.
- `resources/presets/`: bundled templates and `sing-box` preset rule sets.
- `scripts/`: parity, completion, target-host, Docker, and packaging validators.
- `docs/`: parity audit and target-host validation runbook.

## Data and privacy

Sandfox stores profile content, settings, rules, logs, and backups locally in the user data directory. Subscription URLs and API secrets are stored locally by the application; do not paste them into bug reports. Logs are local unless you choose to share them.

The project has no telemetry, account service, or hosted backend.

## Compatibility notes

- macOS is the primary development and desktop test platform.
- Windows NSIS packaging is implemented, but signing and service-lifecycle evidence require a Windows host.
- Linux packages are implemented for GTK4 and WebKitGTK 6. Full AppImage, DEB, RPM, and Arch validation requires a Linux or Docker environment.
- The helper is compatible with RoverService endpoints and uses platform-specific launch daemons, Windows services, or systemd units.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request. Bug reports with platform, version, reproduction, logs, and expected versus actual behavior are especially useful.

## Security

Report security issues through private vulnerability reporting. Do not open a public issue for privilege escalation, command execution, secrets exposure, or other exploitable behavior. See [SECURITY.md](SECURITY.md).

## License

Sandfox is available under the [MIT License](LICENSE). Third-party dependencies remain under their own licenses.
