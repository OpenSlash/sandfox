# Rover Parity Audit

Objective: reproduce Rover capabilities in the Sandfox Wails v3 + Go application while keeping the UI in the existing shadcn-style React component model with lucide icons.

## Success criteria

- Wails API covers every Rover preload IPC method.
- The main UI exposes the Rover platform areas: dashboard, profiles, proxies, policies, DNS, rule sets, connections, logs, and settings.
- Profile and subscription handling supports Clash YAML, sing-box JSON, share links, proxy providers, rule providers, subscription userinfo, refresh, and validation.
- Rule and node conversion covers Rover's Clash node types and Clash route rule types.
- Built-in preset rule set resources cover Rover's sing-box preset list.
- Built-in preset templates cover Rover's template index and preserve template DNS/settings semantics.
- Config generation emits runnable sing-box config and preserves unsupported Clash-only metadata without emitting invalid sing-box fields.
- RoverService-compatible helper covers status, sing-box control, DNS control/query, process listing/killing, path checks, and file reads.
- Platform integration covers system proxy, auto-start, privileged helper install/control, and packaging for macOS, Windows, and Linux.
- Verification commands exist for API/rule/node/helper endpoint parity and for the Go test suite.
- A completion audit command distinguishes automated parity evidence from real platform validation gates.

## Evidence checklist

| Requirement | Evidence |
| --- | --- |
| Rover reference freshness | `wails3 task audit:rover` verifies `/tmp/rover-source` HEAD `2e31d5ae9b409b94bef45a950a2344498693cd52` matches `origin/HEAD` for `https://github.com/roverlab/rover.git`. |
| Go + Wails v3 baseline | `go.mod` requires `github.com/wailsapp/wails/v3`, Go code imports Wails v3 `application`, the frontend depends on `@wailsio/runtime`, and `wails3 task audit:rover` checks this baseline. |
| API parity | `wails3 task parity:rover` reports Rover source ref `2e31d5ae9b409b94bef45a950a2344498693cd52`, Rover API methods 98, Wails methods 210, missing 0, and weak channel-tail-only API mappings 0. |
| Node conversion parity | `wails3 task parity:rover` reports missing node types: none for anytls, http, hysteria2, socks5, ss, trojan, tuic, vless, vmess. `TestRoverProxyNodeTypesConvertToSingBoxOutbounds` verifies sing-box outbound generation for all Rover node types, including TLS/Reality, transports, SIP003 plugin options, Hysteria2 bandwidth/obfs, TUIC options, AnyTLS session options, and SOCKS5 `version: "5"`. |
| Clash route rule parity | `wails3 task parity:rover` reports missing Clash rule types: none for Rover's 17 rule types. `TestImportClashConfigRules` verifies Rover route rule conversions plus extended process/package rules and Clash script preservation without emitting invalid sing-box fields. |
| RoverService endpoint parity | `wails3 task parity:rover` reports missing RoverService endpoints: none. |
| Frontend platform areas | `wails3 task audit:rover` checks that the React navigation and render paths expose dashboard, proxies, profiles, policies, DNS, rule sets, connections, logs, and settings, and that the frontend loads the corresponding service data. |
| shadcn-style frontend icons | The React frontend depends on `lucide-react` and `wails3 task audit:rover` checks that `frontend/src/App.tsx` imports lucide icons instead of local letter SVG placeholders. |
| Preset rule set parity | `wails3 task parity:rover` reports Rover preset rule sets 2212 and Sandfox embedded preset rule sets 2212. |
| Preset template parity | `wails3 task parity:rover` reports Rover templates 3 and missing Rover templates: none. `TestRoverPresetTemplatesAreImportedWithSettingsAndRawDNS` verifies `templates/3.json`, `templates/4.json`, `templates/5.json`, Rover DNS server headers, raw fakeip DNS server, raw DNS policies, and preference-backed DNS settings. |
| Profile and subscription handling | `wails3 task audit:rover` checks service methods and behavior tests covering Clash YAML profiles, sing-box JSON outbounds, share links, proxy providers, rule providers, subscription userinfo, refresh scheduling/refresh errors, and invalid subscription validation. |
| Config generation | `wails3 task audit:rover` checks config generate/preview/diff/validate/current-rule methods and tests proving generated sing-box config reflects Rover platform settings while preserving unsupported Clash-only metadata outside emitted config. |
| Platform integration | `wails3 task audit:rover` checks system proxy and auto-launch methods, privileged helper controls, frontend service-control actions, LaunchDaemon/systemd/Windows helper templates, and TUN core start through RoverService. |
| Automated tests | `go test ./...` passes. The macOS SDK linker warnings are non-fatal. |
| macOS build | `wails3 build` passes and produces Mach-O arm64 `bin/sandfox` and `bin/roverservice`. |
| macOS app bundle | `wails3 task package` passes and includes `bin/sandfox.app/Contents/MacOS/sandfox` and `bin/sandfox.app/Contents/Resources/roverservice` as Mach-O arm64. `wails3 task audit:rover` also requires these artifacts to be newer than the key app/helper source files. |
| Windows build/package | `wails3 task windows:package` passes for ARM64 and `ARCH=amd64 wails3 task windows:package` passes for x64. Current evidence includes refreshed `bin/sandfox-arm64-installer.exe` and `bin/sandfox-amd64-installer.exe`; after the amd64 build, `bin/sandfox.exe` and `bin/roverservice.exe` are Windows x86-64 binaries. `wails3 task audit:rover` also requires both installers to be newer than the key app/helper source files. |
| Windows RoverService pipe client | Sandfox now uses `github.com/Microsoft/go-winio` in `rover_service_dial_windows.go` to connect to `\\.\pipe\roverservice`; Windows amd64 and arm64 cross-builds pass. |
| Helper runtime socket | Running `bin/roverservice run` with `SANDFOX_ROVERSERVICE_SOCKET` responds successfully to `/status` and `/dns/query`. |
| Dashboard TUN start path | The top-level Start Core action checks RoverService when TUN is enabled, installs the helper when missing, starts it when the socket is unavailable, then starts sing-box through the helper. |
| Linux helper build | `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/roverservice` succeeds and produces a statically linked Linux x86-64 ELF helper. |
| Linux deb content | Historical nfpm inspection confirmed the intended deb paths `/usr/local/bin/sandfox` and `/usr/local/lib/sandfox/roverservice`; this is not accepted as current completion evidence without `linux-package.json`. |
| Linux Docker readiness | `scripts/docker-ready.mjs` checks both the default Docker context and Docker Desktop socket with a bounded timeout, so Linux packaging fails fast instead of hanging when Docker is unhealthy. |
| Current helper safe validation | `wails3 task audit:rover` runs the non-mutating `scripts/roverservice-target-check.mjs` path and requires packaged helper discovery, binary/file validation, helper freshness, `help`, and `status` checks to pass on the current host. In non-mutating evidence, `mutating-service-cycle` is marked `skipped: true` and does not replace target-host lifecycle evidence. |
| Completion audit | `wails3 task audit:rover` runs `scripts/rover-completion-audit.mjs`. Current local result is expected to fail until `linux-package.json`, `macos-service.json`, `windows-service.json`, and `linux-service.json` are produced on target hosts. Docker readiness alone is not accepted as Linux package completion evidence, and manual service override flags are not accepted. |
| Target service validation | `wails3 task validate:roverservice` runs `scripts/roverservice-target-check.mjs`. By default it only performs safe helper discovery/help/status checks; with `SANDFOX_VALIDATE_SERVICE_MUTATION=1` it runs install/status/stop/start/uninstall on a target host. Target service evidence must include schema `sandfox-rover-target-v1`, `helper-fresh`, and `helper-sha256`, proving the helper is newer than key app/helper source files and recording its hash. Set `SANDFOX_VALIDATE_EVIDENCE_OUT` to write pure JSON evidence. `wails3 task audit:rover` can consume `macos-service.json`, `windows-service.json`, and `linux-service.json` from `SANDFOX_AUDIT_EVIDENCE_DIR`. |
| Target Linux package validation | `wails3 task validate:linux-package` runs `scripts/linux-package-target-check.mjs`. With `SANDFOX_VALIDATE_LINUX_PACKAGE_MUTATION=1`, it runs the Linux package command and checks AppImage, DEB, RPM, and Arch Linux package artifacts. The target evidence must include schema `sandfox-rover-target-v1`, prove Linux package artifacts are newer than key app/helper source files, and record artifact SHA-256 hashes. Set `SANDFOX_VALIDATE_EVIDENCE_OUT` to write pure JSON evidence. `wails3 task audit:rover` can consume `linux-package.json` from `SANDFOX_AUDIT_EVIDENCE_DIR`. |
| Target evidence command printer and bundle | `wails3 task audit:rover:commands` prints the current macOS, Windows, Linux service, Linux package, and final audit commands used to collect the remaining target-host evidence. `wails3 task audit:rover:evidence-bundle` writes `/tmp/sandfox-rover-evidence/target-evidence-commands.md`, refreshes non-mutating `/tmp/sandfox-rover-evidence/current-helper-safe.json`, writes `/tmp/sandfox-rover-evidence/pending-target-evidence.json`, and refreshes `/tmp/sandfox-rover-evidence.tar.gz`. The completion audit requires both tasks, the pending-evidence manifest generator, and common Go-bin PATH setup in the generated commands. |
| Target validation runbook | `docs/target-validation-runbook.md` maps the remaining macOS, Windows, Linux service lifecycle and Linux package gates to exact commands and JSON evidence files. |

## Known non-equivalent or environment-bound items

- Clash `script` has no sing-box equivalent. Rover's own `convertClashRuleToRouteRule` does not convert it either. Sandfox preserves it under `settings.experimental.sandfox_unsupported.clash_script`, warns in previews, and does not emit it to sing-box config.
- Real macOS LaunchDaemon install/start/stop still requires an administrator prompt and changes system state. This has not been run in this audit.
- Real Windows Service install/start/stop still requires a Windows host and UAC. This has not been run in this audit.
- Real Linux systemd install/start/stop still requires a Linux host with sudo or pkexec. This has not been run in this audit.
- Full Linux AppImage/DEB/RPM/Arch packaging is blocked on this macOS host because Docker is not responding. The default context `docker ps` hangs, and `DOCKER_HOST=unix://$HOME/.docker/run/docker.sock docker info` times out. `DOCKER_READY_TIMEOUT_MS=3000 node scripts/docker-ready.mjs` confirms both Docker endpoints time out. Do not treat Linux full packaging as verified until `wails3 task linux:package` completes on a working Docker/Linux environment.

## Current conclusion

The current strict completion audit result is `25/29`. Implementation and automated parity checks cover the Rover API surface, supported node/rule conversions, profile/subscription behavior, config generation, preset rule sets, preset templates, helper endpoint surface, frontend platform areas, shadcn-style lucide icons, platform integration controls, builds, packaging for macOS/Windows, and helper runtime behavior.

The goal should not be marked complete until these target-host evidence files exist and pass `wails3 task audit:rover` with `SANDFOX_AUDIT_EVIDENCE_DIR`:

- `/tmp/sandfox-rover-evidence/macos-service.json`
- `/tmp/sandfox-rover-evidence/windows-service.json`
- `/tmp/sandfox-rover-evidence/linux-service.json`
- `/tmp/sandfox-rover-evidence/linux-package.json`

Current local blockers: non-interactive sudo is unavailable on this macOS host, and Docker readiness times out for both the default context and Docker Desktop socket.
