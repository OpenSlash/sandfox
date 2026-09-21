# Security Policy

## Supported versions

Sandfox is preparing its first public release. Fixes target `main`, and security fixes are included in the next tagged release.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/OpenSlash/sandfox/security/advisories/new) for vulnerabilities. Do not disclose exploit details in public issues, pull requests, or discussions.

Please include:

- affected component: desktop UI, configuration generator, privileged helper, updater, package, or other path
- affected platform and architecture
- a minimal reproduction and any vulnerable configuration
- impact and prerequisites
- suggested mitigation, if known

You may submit in English or Chinese. A maintainer will normally respond within 7 days. Please allow reasonable time for coordinated disclosure before public publication.

## Scope notes

Sandfox integrates with `sing-box` and installs a platform-specific helper for privileged service management. Reports are especially valuable for:

- helper authentication, socket permissions, and lifecycle controls
- command-line construction and binary path selection
- generated configuration boundary handling
- subscription parsing and profile import
- update or package integrity

Public discussion and non-sensitive hardening proposals are welcome in normal issues.
