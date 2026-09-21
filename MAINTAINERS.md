# Maintenance Guide

## Ownership

- Project lead: JairoGuo
- Repository: [HoltAI/sandfox](https://github.com/HoltAI/sandfox)
- Security reports: use private vulnerability reporting according to [SECURITY.md](SECURITY.md)

New maintainers should be active contributors for at least one release cycle, demonstrate understanding of platform-specific risks, and be added by the project lead.

## Release owner checklist

1. Assign a release owner.
2. Open or update a release issue containing scope, known issues, verification evidence, and blockers.
3. Ensure CI is green on `main`.
4. Run the release verification below on affected platforms.
5. Build and package on native runners.
6. Record hashes, package paths, and any signing exceptions.
7. Create a GitHub release, upload artifacts, and publish notes.
8. Triage immediate regressions before starting the next change batch.

## Release verification

Run from a clean checkout:

```sh
export PATH="$HOME/go/bin:$PATH"
wails3 task verify
wails3 task build
```

For release candidates or platform/helper changes:

```sh
wails3 task package
```

On macOS this produces `bin/sandfox.app`; on Windows it produces an NSIS installer; on Linux it produces AppImage, DEB, RPM, and Arch packages.

The project distinguishes automated verification from target-host evidence. See `docs/target-validation-runbook.md` for privileged helper and full Linux packaging gates.

## Versioning

Use semantic versioning:

- major: incompatible profile, configuration, helper protocol, or CLI behavior changes
- minor: backward-compatible features and meaningful platform capabilities
- patch: fixes and packaging corrections

Tag releases as `vMAJOR.MINOR.PATCH` on the release commit.

## Maintenance cadence

- Weekly: triage new issues and pull requests, reproduce high-priority regressions.
- Monthly: review stale issues, dependency updates, and platform compatibility changes.
- Each release: refresh compatibility notes, screenshots, roadmap, and target-host evidence.

## Feature and issue labels

- `bug`: confirmed or likely defect
- `platform/macos`, `platform/windows`, `platform/linux`: affected platform
- `area/helper`, `area/config`, `area/profiles`, `area/policies`, `area/dns`, `area/ui`, `area/packaging`
- `needs-repro`: missing platform, version, logs, or reproduction
- `good first issue`: narrow and suitable for a new contributor
