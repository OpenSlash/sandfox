# Sandfox

Sandfox is a Wails v3 + Go desktop client that tracks Rover capabilities with a React UI, shadcn-style local components, and lucide icons. It manages profiles, proxy nodes, policies, DNS, rule sets, runtime logs, sing-box config generation, and a RoverService-compatible privileged helper.

## Requirements

- Go with Wails v3 installed as `wails3`
- Node.js and npm
- sing-box available on `PATH` or configured in Settings
- Optional: Docker Desktop for Linux cross-packaging on macOS/Windows
- Optional: NSIS for Windows installer packaging

If Wails is installed into the default Go bin directory, add it to your shell before running project tasks:

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

Package the current platform:

```sh
wails3 task package
```

## Verification

Run the core verification suite:

```sh
wails3 task verify
```

This runs:

- `wails3 task parity:rover`
- `go test ./...`

The Rover parity check reads a local Rover checkout from `/tmp/rover-source` by default. Override it with:

```sh
ROVER_SOURCE=/path/to/rover node scripts/rover-parity-check.mjs
```

The parity check verifies:

- Rover preload API coverage in Wails bindings
- Rover Clash node type coverage
- Rover Clash route rule type coverage
- RoverService helper HTTP endpoint coverage
- Rover sing-box preset rule set count
- Rover preset template paths

The completion audit also verifies the Go + Wails v3 baseline, main frontend platform areas, shadcn-style lucide icons, profile/subscription behavior, config generation behavior, platform integration controls, and target-host evidence gates.

Run the stricter completion audit:

```sh
wails3 task audit:rover
```

This command is expected to fail until the environment-bound gates are verified on real macOS, Windows, and Linux hosts. It separates automated parity evidence and local package artifacts from service-install and Linux-packaging evidence.

Print the target-host evidence commands:

```sh
export PATH="$HOME/go/bin:$PATH"
wails3 task audit:rover:commands
```

Write the command file, refresh the current safe helper evidence, write the pending target evidence manifest, and update `/tmp/sandfox-rover-evidence.tar.gz`:

```sh
export PATH="$HOME/go/bin:$PATH"
wails3 task audit:rover:evidence-bundle
```

Check the RoverService helper on a target host:

```sh
export PATH="$HOME/go/bin:$PATH"
wails3 task validate:roverservice
```

By default this only finds the helper and runs safe `help`/`status` checks. To verify the full privileged lifecycle on a disposable target host, run it with:

```sh
export PATH="$HOME/go/bin:$PATH"
SANDFOX_VALIDATE_SERVICE_MUTATION=1 \
SANDFOX_VALIDATE_EVIDENCE_OUT=/path/to/evidence/macos-service.json \
wails3 task validate:roverservice
```

To feed target-host evidence back into the completion audit, save the JSON output as:

- `macos-service.json`
- `windows-service.json`
- `linux-service.json`
- `linux-package.json`

The bundle's `current-helper-safe.json` is non-mutating current-host evidence. Its service lifecycle check is marked `skipped: true` and does not replace the target-host service JSON files above.

Then run:

```sh
export PATH="$HOME/go/bin:$PATH"
SANDFOX_AUDIT_EVIDENCE_DIR=/path/to/evidence wails3 task audit:rover
```

For Linux package evidence, run on a Linux or working Docker target:

```sh
export PATH="$HOME/go/bin:$PATH"
SANDFOX_VALIDATE_LINUX_PACKAGE_MUTATION=1 \
SANDFOX_VALIDATE_EVIDENCE_OUT=/path/to/evidence/linux-package.json \
wails3 task validate:linux-package
```

On a non-Linux host with a working `wails-cross` Docker image, run the full Linux package chain inside Docker:

```sh
export PATH="$HOME/go/bin:$PATH"
SANDFOX_VALIDATE_LINUX_PACKAGE_MUTATION=1 \
SANDFOX_LINUX_PACKAGE_DOCKER=1 \
SANDFOX_VALIDATE_EVIDENCE_OUT=/path/to/evidence/linux-package.json \
wails3 task validate:linux-package
```

If GitHub downloads for AppImage tooling are unreliable, pre-place `linuxdeploy-<arch>.AppImage` and `AppRun-<arch>` in `build/linux/appimage/cache/`; `scripts/linux-package-docker-target.sh` reuses those files when present.

Detailed target-host steps live in:

```sh
docs/target-validation-runbook.md
```

## Packaging

macOS:

```sh
wails3 task package
```

Windows:

```sh
wails3 task windows:package
ARCH=amd64 wails3 task windows:package
```

The Windows task writes `bin/sandfox.exe` and `bin/roverservice.exe` for the requested architecture, then emits an architecture-specific installer such as `bin/sandfox-arm64-installer.exe` or `bin/sandfox-amd64-installer.exe`.

Linux:

```sh
wails3 task linux:package
```

Linux cross-packaging uses Docker. The Docker preflight is bounded by `scripts/docker-ready.mjs` so an unhealthy Docker daemon fails quickly instead of hanging. Adjust the timeout if needed:

```sh
DOCKER_READY_TIMEOUT_MS=30000 node scripts/docker-ready.mjs
```

## Rover parity status

The current audit lives in:

```sh
docs/rover-parity-audit.md
```

Current strict completion audit result: `25/29`.

Implementation and automated checks cover API parity, supported node/rule conversion parity, profile/subscription handling, sing-box config generation, Rover preset rule set/template parity, RoverService endpoint parity, frontend platform areas, shadcn-style lucide icons, platform integration controls, macOS/Windows packaging, and helper socket runtime checks.

Known environment-bound gaps:

- Real macOS LaunchDaemon install/start/stop requires administrator authorization.
- Real Windows Service install/start/stop requires a Windows host and UAC.
- Real Linux systemd install/start/stop requires a Linux host with sudo or pkexec.
- Full Linux AppImage/DEB/RPM/Arch packaging requires a working Docker/Linux environment.

Do not mark Rover parity complete until `wails3 task audit:rover` passes with these target-host evidence files:

- `macos-service.json`
- `windows-service.json`
- `linux-service.json`
- `linux-package.json`

## Key paths

- `service.go`: main Wails service, config generation, profile/rule/DNS logic
- `platform.go`: platform integration and privileged service management
- `cmd/roverservice`: RoverService-compatible helper
- `frontend/src/App.tsx`: React UI
- `scripts/rover-parity-check.mjs`: Rover parity verifier
- `scripts/docker-ready.mjs`: bounded Docker readiness check
