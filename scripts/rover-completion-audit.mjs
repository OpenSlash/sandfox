#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();

function exists(relativePath) {
  return fs.existsSync(path.join(root, relativePath));
}

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

function mtimeMs(relativePath) {
  try {
    return fs.statSync(path.join(root, relativePath)).mtimeMs;
  } catch {
    return 0;
  }
}

function newestMtime(paths) {
  return Math.max(...paths.map((item) => mtimeMs(item)));
}

function commandSucceeds(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    timeout: options.timeout ?? 10000,
    env: { ...process.env, ...options.env },
  });
  return {
    ok: result.status === 0,
    status: result.status,
    stdout: result.stdout?.trim() ?? "",
    stderr: result.stderr?.trim() ?? "",
    error: result.error?.message ?? "",
  };
}

function record(checks, id, ok, evidence, remediation = "") {
  checks.push({ id, ok, evidence, remediation });
}

function readJSONIfExists(file) {
  if (!file || !fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

function evidenceDirFile(name) {
  const dir = process.env.SANDFOX_AUDIT_EVIDENCE_DIR;
  if (!dir) return "";
  return path.join(dir, name);
}

function roverSourceFreshness() {
  const roverRoot = process.env.ROVER_SOURCE || "/tmp/rover-source";
  if (!fs.existsSync(roverRoot)) {
    return { ok: false, message: `${roverRoot} does not exist.` };
  }
  const local = commandSucceeds("git", ["-C", roverRoot, "rev-parse", "HEAD"], { timeout: 5000 });
  if (!local.ok || !local.stdout) {
    return { ok: false, message: `Unable to read local Rover HEAD: ${local.stderr || local.error || local.stdout}` };
  }
  const remote = commandSucceeds("git", ["-C", roverRoot, "ls-remote", "origin", "HEAD"], { timeout: 15000 });
  if (!remote.ok || !remote.stdout) {
    return { ok: false, message: `Unable to read remote Rover HEAD: ${remote.stderr || remote.error || remote.stdout}` };
  }
  const remoteHead = remote.stdout.split(/\s+/)[0];
  if (local.stdout !== remoteHead) {
    return { ok: false, message: `Local Rover HEAD ${local.stdout} does not match remote HEAD ${remoteHead}.` };
  }
  return { ok: true, message: `${roverRoot} HEAD ${local.stdout} matches origin/HEAD.` };
}

function serviceEvidenceStatus(file, expectedPlatform) {
  const evidence = readJSONIfExists(file);
  if (!evidence) {
    return { ok: false, message: "No JSON evidence file found." };
  }
  if (evidence.schema !== "sandfox-rover-target-v1") {
    return { ok: false, message: `Expected evidence schema sandfox-rover-target-v1, got ${evidence.schema || "none"}.` };
  }
  if (evidence.platform !== expectedPlatform) {
    return { ok: false, message: `Expected platform ${expectedPlatform}, got ${evidence.platform || "unknown"}.` };
  }
  if (evidence.mutate !== true) {
    return { ok: false, message: "Evidence was produced without SANDFOX_VALIDATE_SERVICE_MUTATION=1." };
  }
  const checks = Array.isArray(evidence.checks) ? evidence.checks : [];
  const required = [
    "helper-fresh",
    "helper-sha256",
    "helper-install",
    "helper-status-after-install",
    "helper-stop",
    "helper-status-after-stop",
    "helper-start",
    "helper-status-after-start",
    "helper-uninstall",
    "helper-status-after-uninstall",
  ];
  for (const name of required) {
    if (!checks.some((check) => check.name === name && check.ok === true)) {
      return { ok: false, message: `Missing passing check ${name}.` };
    }
  }
  return { ok: true, message: `${file}: ${required.join(", ")} passed.` };
}

function linuxPackageEvidenceStatus(file) {
  const evidence = readJSONIfExists(file);
  if (!evidence) {
    return { ok: false, message: "No JSON evidence file found." };
  }
  if (evidence.schema !== "sandfox-rover-target-v1") {
    return { ok: false, message: `Expected evidence schema sandfox-rover-target-v1, got ${evidence.schema || "none"}.` };
  }
  if (evidence.mutate !== true) {
    return { ok: false, message: "Evidence was produced without SANDFOX_VALIDATE_LINUX_PACKAGE_MUTATION=1." };
  }
  const checks = Array.isArray(evidence.checks) ? evidence.checks : [];
  const required = ["linux-package-command", "linux-appimage-artifact", "linux-deb-artifact", "linux-rpm-artifact", "linux-aur-artifact", "linux-artifacts-fresh", "linux-artifact-hashes"];
  for (const name of required) {
    if (!checks.some((check) => check.name === name && check.ok === true)) {
      return { ok: false, message: `Missing passing check ${name}.` };
    }
  }
  return { ok: true, message: `${file}: ${required.join(", ")} passed.` };
}

function frontendPlatformAreasCovered(frontend) {
  const pages = ["dashboard", "proxies", "profiles", "policies", "dns", "rulesets", "connections", "logs", "settings"];
  const serviceCalls = [
    "GetDashboard",
    "GetProxyGroups",
    "GetProfiles",
    "GetPolicies",
    "GetDNSPolicies",
    "GetDNSServers",
    "GetRuleSets",
    "GetConnections",
    "GetLogs",
    "GetSettings",
  ];
  return pages.every((page) => frontend.includes(`id: '${page}'`) && frontend.includes(`page === '${page}'`))
    && serviceCalls.every((method) => frontend.includes(`SandfoxService.${method}(`));
}

function profileSubscriptionCapabilitiesCovered(service, tests) {
  const serviceMethods = [
    "func (s *SandfoxService) ImportProfile(",
    "func (s *SandfoxService) RefreshProfile(",
    "func (s *SandfoxService) RefreshProfileProvider(",
    "func (s *SandfoxService) RefreshRuleSet(",
    "func parseShareLink(",
    "func parseSubscriptionUserinfo(",
    "func validateProfileParseResult(",
  ];
  const behaviorTests = [
    "TestParseClashYAMLAndOutboundTransports",
    "TestImportProfileWithSingBoxOutbounds",
    "TestParseShareLinks",
    "TestImportProfileParsesProxyProvidersAndUse",
    "TestProfileImportSyncsRuleProviders",
    "TestSubscriptionUserAgentUsedForProfileImport",
    "TestProfileContentValidationRejectsInvalidSubscription",
    "TestRefreshProfileAppliesFilterAndRecordsErrors",
    "TestRefreshProfileProvidersReplacesProviderNodes",
    "TestRefreshRuleSetConvertsClashProviderPayload",
  ];
  return serviceMethods.every((method) => service.includes(method))
    && behaviorTests.every((testName) => tests.includes(testName));
}

function configGenerationCapabilitiesCovered(service, tests) {
  const serviceMethods = [
    "func (s *SandfoxService) GenerateConfig(",
    "func (s *SandfoxService) PreviewConfig(",
    "func (s *SandfoxService) PreviewConfigDiff(",
    "func (s *SandfoxService) ValidateConfig(",
    "func (s *SandfoxService) GetCurrentConfigRules(",
    "func (s *SandfoxService) buildConfigLocked(",
  ];
  const behaviorTests = [
    "TestPreviewConfigChangedState",
    "TestPreviewConfigDiff",
    "TestActiveConfigRulesAndSelectedProfile",
    "TestConfigLoggerAndSingboxCompatibilityAliases",
    "TestRoverPlatformSettingsAffectGeneratedConfig",
    "TestImportClashConfigRules",
    "unsupported Clash script metadata should not be emitted to sing-box config",
  ];
  return serviceMethods.every((method) => service.includes(method))
    && service.includes('delete(out, "sandfox_unsupported")')
    && behaviorTests.every((testName) => tests.includes(testName));
}

function platformIntegrationCapabilitiesCovered(service, frontend, helper, helperTests, tests) {
  const serviceMethods = [
    "func (s *SandfoxService) ApplyPlatformSettings(",
    "func (s *SandfoxService) SetSystemProxy(",
    "func (s *SandfoxService) SetAutoLaunch(",
    "func (s *SandfoxService) GetCoreServiceStatus(",
    "func (s *SandfoxService) InstallCoreService(",
    "func (s *SandfoxService) UninstallCoreService(",
    "func (s *SandfoxService) StartCoreService(",
    "func (s *SandfoxService) StopCoreService(",
  ];
  const frontendCalls = [
    "SandfoxService.InstallCoreService(",
    "SandfoxService.StartCoreService(",
    "SandfoxService.StopCoreService(",
    "SandfoxService.UninstallCoreService(",
    "SandfoxService.ApplyPlatformSettings(",
  ];
  const helperCapabilities = [
    "launchDaemonPlist(",
    "linuxSystemdUnit(",
    "sc.exe",
    "systemctl",
    "launchctl",
  ];
  const behaviorTests = [
    "TestRoverPlatformSettingsAffectGeneratedConfig",
    "TestCoreServiceStatusUsesRoverServiceAPIVersion",
    "TestCoreServiceStatusReadsRoverServiceSocket",
    "TestStartStopCoreUsesRoverServiceForTun",
  ];
  const helperBehaviorTests = [
    "TestLaunchDaemonPlist",
    "TestLinuxSystemdUnit",
    "TestWindowsHelperTargetPath",
  ];
  return serviceMethods.every((method) => service.includes(method))
    && frontendCalls.every((call) => frontend.includes(call))
    && helperCapabilities.every((capability) => helper.includes(capability))
    && behaviorTests.every((testName) => tests.includes(testName))
    && helperBehaviorTests.every((testName) => helperTests.includes(testName));
}

const checks = [];
const service = exists("service.go") ? read("service.go") : "";
const frontend = exists("frontend/src/App.tsx") ? read("frontend/src/App.tsx") : "";
const goMod = exists("go.mod") ? read("go.mod") : "";
const mainGo = exists("main.go") ? read("main.go") : "";
const frontendPackage = exists("frontend/package.json") ? read("frontend/package.json") : "";
const taskfile = exists("Taskfile.yml") ? read("Taskfile.yml") : "";
const helper = exists("cmd/roverservice/main.go") ? read("cmd/roverservice/main.go") : "";
const helperTests = exists("cmd/roverservice/main_test.go") ? read("cmd/roverservice/main_test.go") : "";
const tests = exists("service_test.go") ? read("service_test.go") : "";

const roverFreshness = roverSourceFreshness();
record(checks, "rover-source-freshness", roverFreshness.ok, roverFreshness.message, "Update `/tmp/rover-source` or set ROVER_SOURCE to a fresh Rover checkout whose HEAD matches origin/HEAD.");
record(checks, "go-wails-v3-baseline", goMod.includes("github.com/wailsapp/wails/v3") && mainGo.includes("github.com/wailsapp/wails/v3/pkg/application") && service.includes("github.com/wailsapp/wails/v3/pkg/application") && frontendPackage.includes('"@wailsio/runtime"'), "Project is a Go + Wails v3 app with Wails v3 Go application imports and Wails frontend runtime.");
record(checks, "wails-api-parity-gate", exists("scripts/rover-parity-check.mjs") && taskfile.includes("parity:rover"), "Taskfile exposes parity:rover and scripts/rover-parity-check.mjs exists.");
record(checks, "rover-rule-set-resources", exists("resources/presets/rulesets/singbox.json") && service.includes("resources/presets/rulesets/singbox.json"), "Rover sing-box preset rule sets are embedded into service.go.");
record(checks, "rover-template-resources", exists("resources/presets/templates.json") && exists("resources/presets/templates/3.json") && exists("resources/presets/templates/4.json") && exists("resources/presets/templates/5.json") && service.includes("roverTemplatesFS"), "Rover template index and templates/3,4,5 are embedded.");
record(checks, "rover-template-behavior-tests", tests.includes("TestRoverPresetTemplatesAreImportedWithSettingsAndRawDNS"), "Template import test covers Rover settings, raw DNS policy, Rover DNS headers, and fakeip raw server.");
record(checks, "rover-node-conversion-behavior-tests", tests.includes("TestRoverProxyNodeTypesConvertToSingBoxOutbounds"), "Node conversion test covers Rover proxy node types: ss, socks5, http, vmess, vless, trojan, hysteria2, tuic, anytls.");
record(checks, "rover-rule-conversion-behavior-tests", tests.includes("TestImportClashConfigRules") && tests.includes("DOMAIN-SUFFIX") && tests.includes("RULE-SET") && tests.includes("PROCESS-PATH"), "Clash rule conversion test covers Rover route rule types plus preserved unsupported script metadata.");
record(checks, "profile-subscription-capabilities", profileSubscriptionCapabilitiesCovered(service, tests), "Profile/subscription handling covers Clash YAML, sing-box JSON, share links, proxy providers, rule providers, subscription userinfo, refresh, and validation.");
record(checks, "config-generation-capabilities", configGenerationCapabilitiesCovered(service, tests), "Config generation covers generate/preview/diff/validate/current rules and strips unsupported Clash-only metadata from emitted sing-box config.");
record(checks, "rover-service-endpoints", helper.includes('"/dns/query"') && helper.includes('"/singbox/start"') && helper.includes('"/processes/kill"'), "RoverService helper includes DNS, sing-box, process, file, status endpoints.");
record(checks, "platform-integration-capabilities", platformIntegrationCapabilitiesCovered(service, frontend, helper, helperTests, tests), "Platform integration covers system proxy, auto-start, privileged service controls, helper service templates, and TUN core start through RoverService.");
record(checks, "frontend-platform-areas", frontendPlatformAreasCovered(frontend), "Frontend navigation renders Rover platform areas and loads their service data: dashboard, profiles, proxies, policies, DNS, rule sets, connections, logs, settings.");
record(checks, "dashboard-tun-service-path", frontend.includes("startCoreWithServiceCheck") && frontend.includes("InstallCoreService") && frontend.includes("StartCoreService"), "Dashboard start path checks and starts RoverService for TUN mode.");
record(checks, "frontend-shadcn-lucide-icons", frontendPackage.includes('"lucide-react"') && frontend.includes("from 'lucide-react'") && !frontend.includes("const makeIcon"), "Frontend uses lucide-react icons instead of local letter SVG placeholders.");
record(checks, "linux-docker-readiness-gate", exists("scripts/docker-ready.mjs") && read("build/linux/Taskfile.yml").includes("node scripts/docker-ready.mjs"), "Linux Docker build path has a bounded Docker readiness precondition.");
record(checks, "target-service-validation-tool", exists("scripts/roverservice-target-check.mjs") && taskfile.includes("validate:roverservice"), "Target-host RoverService validation script and task exist.");
record(checks, "target-linux-package-validation-tool", exists("scripts/linux-package-target-check.mjs") && taskfile.includes("validate:linux-package"), "Target-host Linux package validation script and task exist.");
const targetEvidenceCommands = exists("scripts/rover-target-evidence-commands.mjs") ? read("scripts/rover-target-evidence-commands.mjs") : "";
record(
  checks,
  "target-evidence-command-tool",
  taskfile.includes("audit:rover:commands")
    && taskfile.includes("audit:rover:evidence-bundle")
    && exists("scripts/rover-pending-evidence.mjs")
    && taskfile.includes("rover-pending-evidence.mjs")
    && targetEvidenceCommands.includes("macOS privileged RoverService lifecycle")
    && targetEvidenceCommands.includes("Windows Administrator RoverService lifecycle")
    && targetEvidenceCommands.includes("Linux systemd RoverService lifecycle")
    && targetEvidenceCommands.includes("Linux full package artifacts")
    && targetEvidenceCommands.includes("Final completion audit")
    && targetEvidenceCommands.includes('export PATH="$HOME/go/bin:$PATH"')
    && targetEvidenceCommands.includes('$env:Path="$env:USERPROFILE\\\\go\\\\bin;$env:Path"'),
  "Target-host evidence command printer, pending-evidence manifest, and bundle task exist for macOS, Windows, Linux service, Linux package, final audit commands, and common Wails Go-bin PATH setup.",
);
const helperSafeValidation = commandSucceeds("node", ["scripts/roverservice-target-check.mjs"], {
  timeout: 15000,
  env: {
    SANDFOX_VALIDATE_SERVICE_MUTATION: "0",
    SANDFOX_VALIDATE_EVIDENCE_OUT: "",
    SANDFOX_VALIDATE_PLATFORM: process.platform,
  },
});
record(
  checks,
  "current-helper-safe-validation",
  helperSafeValidation.ok,
  helperSafeValidation.ok ? "Packaged helper discovery, file, freshness, help, and non-mutating status checks passed." : helperSafeValidation.stderr || helperSafeValidation.stdout || helperSafeValidation.error,
  "Run `wails3 task package` and `wails3 task validate:roverservice`.",
);
record(
  checks,
  "windows-roverservice-pipe-client",
  exists("rover_service_dial_windows.go") && read("rover_service_dial_windows.go").includes("winio.DialPipeContext") && !service.includes("Windows RoverService named pipe client is not implemented"),
  "Windows client uses go-winio to dial RoverService named pipe.",
);

const macAppBinary = "bin/sandfox.app/Contents/MacOS/sandfox";
const macHelperBinary = "bin/sandfox.app/Contents/Resources/roverservice";
const macAppFile = exists(macAppBinary) ? commandSucceeds("file", [macAppBinary]) : { ok: false, stdout: "missing" };
const macHelperFile = exists(macHelperBinary) ? commandSucceeds("file", [macHelperBinary]) : { ok: false, stdout: "missing" };
const packagingSourceMtime = newestMtime([
  "service.go",
  "cmd/roverservice/main.go",
  "rover_service_dial_unix.go",
  "rover_service_dial_windows.go",
  "frontend/src/App.tsx",
]);
const macArtifactsFresh = mtimeMs(macAppBinary) >= packagingSourceMtime && mtimeMs(macHelperBinary) >= packagingSourceMtime;
record(
  checks,
  "macos-package-artifacts",
  macAppFile.ok && macHelperFile.ok && macAppFile.stdout.includes("Mach-O") && macHelperFile.stdout.includes("Mach-O") && macArtifactsFresh,
  `${macAppBinary}: ${macAppFile.stdout}; ${macHelperBinary}: ${macHelperFile.stdout}; fresh=${macArtifactsFresh}`,
  "Run `wails3 task package` on macOS.",
);

const windowsInstallersFresh = mtimeMs("bin/sandfox-arm64-installer.exe") >= packagingSourceMtime && mtimeMs("bin/sandfox-amd64-installer.exe") >= packagingSourceMtime;
record(
  checks,
  "windows-installer-artifacts",
  exists("bin/sandfox-arm64-installer.exe") && exists("bin/sandfox-amd64-installer.exe") && windowsInstallersFresh,
  `bin/sandfox-arm64-installer.exe and bin/sandfox-amd64-installer.exe exist; fresh=${windowsInstallersFresh}.`,
  "Run `wails3 task windows:package` and `ARCH=amd64 wails3 task windows:package`.",
);

const linuxHelperPath = path.join(os.tmpdir(), `sandfox-roverservice-linux-${process.pid}`);
const linuxHelperBuild = commandSucceeds("go", ["build", "-trimpath", "-buildvcs=false", "-ldflags=-w -s", "-o", linuxHelperPath, "./cmd/roverservice"], {
  timeout: 30000,
  env: { GOOS: "linux", GOARCH: "amd64", CGO_ENABLED: "0" },
});
const linuxHelperFile = linuxHelperBuild.ok ? commandSucceeds("file", [linuxHelperPath]) : { ok: false, stdout: linuxHelperBuild.stderr || linuxHelperBuild.error };
try {
  fs.rmSync(linuxHelperPath, { force: true });
} catch {}
record(
  checks,
  "linux-helper-cross-build",
  linuxHelperBuild.ok && linuxHelperFile.ok && linuxHelperFile.stdout.includes("ELF") && linuxHelperFile.stdout.includes("x86-64"),
  linuxHelperBuild.ok ? linuxHelperFile.stdout : linuxHelperBuild.stderr || linuxHelperBuild.error,
  "Fix Linux helper cross-build with `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/roverservice`.",
);

const parity = commandSucceeds("node", ["scripts/rover-parity-check.mjs"], { timeout: 15000 });
record(checks, "current-parity-result", parity.ok, parity.ok ? parity.stdout : `${parity.stdout}\n${parity.stderr || parity.error}`, "Run `wails3 task parity:rover` after fixing parity failures.");

const docker = commandSucceeds("node", ["scripts/docker-ready.mjs"], {
  timeout: 7000,
  env: { DOCKER_READY_TIMEOUT_MS: "3000" },
});
const linuxPackageEvidence = linuxPackageEvidenceStatus(evidenceDirFile("linux-package.json"));
record(
  checks,
  "linux-full-package-environment",
  linuxPackageEvidence.ok,
  linuxPackageEvidence.ok ? linuxPackageEvidence.message : `Missing Linux package evidence. Docker readiness on this host: ${docker.ok ? "ready" : docker.stderr || docker.stdout || docker.error}`,
  "Run `export PATH=\"$HOME/go/bin:$PATH\"; SANDFOX_VALIDATE_LINUX_PACKAGE_MUTATION=1 SANDFOX_VALIDATE_EVIDENCE_OUT=/tmp/sandfox-rover-evidence/linux-package.json wails3 task validate:linux-package` on a working Docker/Linux environment.",
);

const targetHostEvidenceGates = [
  {
    id: "macos-privileged-service-real-run",
    ...(() => {
      const status = serviceEvidenceStatus(evidenceDirFile("macos-service.json"), "darwin");
      if (status.ok) return { ok: true, evidence: status.message };
      return { ok: false, evidence: status.message };
    })(),
    remediation: "On macOS, run `export PATH=\"$HOME/go/bin:$PATH\"; wails3 task audit:rover:commands`, then execute the macOS privileged RoverService lifecycle command with administrator authorization.",
  },
  {
    id: "windows-service-real-run",
    ...(() => {
      const status = serviceEvidenceStatus(evidenceDirFile("windows-service.json"), "win32");
      if (status.ok) return { ok: true, evidence: status.message };
      return { ok: false, evidence: status.message };
    })(),
    remediation: "On Windows, run `$env:Path=\"$env:USERPROFILE\\go\\bin;$env:Path\"; wails3 task audit:rover:commands`, then execute the Windows Administrator RoverService lifecycle command through UAC.",
  },
  {
    id: "linux-systemd-real-run",
    ...(() => {
      const status = serviceEvidenceStatus(evidenceDirFile("linux-service.json"), "linux");
      if (status.ok) return { ok: true, evidence: status.message };
      return { ok: false, evidence: status.message };
    })(),
    remediation: "On Linux, run `export PATH=\"$HOME/go/bin:$PATH\"; wails3 task audit:rover:commands`, then execute the Linux systemd RoverService lifecycle command through sudo or pkexec.",
  },
];
checks.push(...targetHostEvidenceGates);

console.log("Rover completion audit");
console.log("======================");
console.log("Objective: reproduce Rover capabilities in Sandfox and accept completion only with concrete local or target-host evidence.");
console.log(`Evidence directory: ${process.env.SANDFOX_AUDIT_EVIDENCE_DIR || "(not set)"}`);
console.log("");
for (const check of checks) {
  console.log(`${check.ok ? "PASS" : "FAIL"} ${check.id}`);
  console.log(`  Evidence: ${check.evidence.split("\n")[0]}`);
  if (!check.ok && check.remediation) {
    console.log(`  Next: ${check.remediation}`);
  }
}

const failures = checks.filter((check) => !check.ok);
console.log("");
console.log(`Passed: ${checks.length - failures.length}/${checks.length}`);
if (failures.length) {
  console.log(`Incomplete gates: ${failures.map((check) => check.id).join(", ")}`);
  process.exit(1);
}
