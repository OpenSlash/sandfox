# Contributing to Sandfox

Thanks for considering a contribution.

## Ways to help

- Reproduce and report desktop, service lifecycle, packaging, or configuration-generation bugs.
- Propose improvements to profile management, policy and DNS editing, diagnostics, or platform integration.
- Improve documentation, screenshots, build reliability, tests, and target-host validation.
- Review pull requests, especially those with platform-specific evidence.

## Before opening an issue

1. Search existing issues.
2. Use the bug or feature request template.
3. Include the platform, architecture, Sandfox version or commit, and expected versus actual behavior.
4. Include relevant logs, generated configuration, and steps to reproduce. Remove subscriptions, credentials, and private network details first.

## Development workflow

1. Install:
   - Go 1.25 or newer
   - Node.js and npm
   - [Wails v3 CLI](https://v3.wails.io)
   - `sing-box` on `PATH`, or configure its path in Settings
2. Fork the repository and create a feature branch.
3. Keep changes focused. Separate unrelated refactors or formatting.
4. Run:
   ```sh
   export PATH="$HOME/go/bin:$PATH"
   wails3 task verify
   ```
   This runs Rover parity checks and all Go tests.
5. Build or package the affected platform when practical.
6. Run `wails3 task audit:rover` when changing APIs, helpers, presets, packaging, or platform integration. Environment-bound gaps are documented in `docs/rover-parity-audit.md`.

## Pull requests

- Describe what changed, why it is needed, and the user-visible behavior.
- Link related issues.
- Add or update tests for behavior changes.
- Document new commands, settings, or packaging requirements.
- State the platforms you tested and the command output or evidence you have.
- Keep privileged service changes narrowly scoped and explain security implications.

## Code style

- Run available formatters before submitting.
- Prefer small functions, explicit errors, and platform-specific code isolated behind clearly named files or build tags.
- Avoid adding secrets, telemetry, or network calls that are unrelated to the user's configured subscriptions and proxy workflows.

## Security

Do not open public issues for privilege escalation, arbitrary command execution, or secrets exposure. Follow [SECURITY.md](SECURITY.md).
