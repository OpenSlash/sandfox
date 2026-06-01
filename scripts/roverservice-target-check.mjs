#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const mutate = process.env.SANDFOX_VALIDATE_SERVICE_MUTATION === "1";
const platform = process.env.SANDFOX_VALIDATE_PLATFORM || process.platform;

function candidateHelpers() {
  if (platform === "win32") {
    return [
      path.join(root, "bin", "roverservice.exe"),
      path.join(process.env.ProgramFiles || "C:\\Program Files", "Rover", "Helper", "roverservice.exe"),
    ];
  }
  if (platform === "darwin") {
    return [
      path.join(root, "bin", "sandfox.app", "Contents", "Resources", "roverservice"),
      path.join(root, "bin", "roverservice"),
      "/Library/PrivilegedHelperTools/roverservice",
    ];
  }
  return [
    path.join(root, "bin", "roverservice"),
    "/usr/local/bin/roverservice",
    "/usr/local/lib/sandfox/roverservice",
  ];
}

function findHelper() {
  for (const helper of candidateHelpers()) {
    if (fs.existsSync(helper)) return helper;
  }
  return "";
}

function run(command, args, timeout = 15000) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    timeout,
  });
  return {
    command: [command, ...args].join(" "),
    ok: result.status === 0,
    status: result.status,
    stdout: (result.stdout || "").trim(),
    stderr: (result.stderr || "").trim(),
    error: result.error?.message || "",
  };
}

function mtimeMs(file) {
  try {
    return fs.statSync(file).mtimeMs;
  } catch {
    return 0;
  }
}

function sourceMtimeMs(relativePath) {
  return mtimeMs(path.join(root, relativePath));
}

function newestSourceMtime() {
  return Math.max(
    sourceMtimeMs("service.go"),
    sourceMtimeMs("cmd/roverservice/main.go"),
    sourceMtimeMs("rover_service_dial_unix.go"),
    sourceMtimeMs("rover_service_dial_windows.go"),
    sourceMtimeMs("frontend/src/App.tsx"),
  );
}

function commandExists(command) {
  const probe = process.platform === "win32"
    ? spawnSync("where", [command], { encoding: "utf8" })
    : spawnSync("sh", ["-c", `command -v ${command}`], { encoding: "utf8" });
  return probe.status === 0;
}

function hasMutationPrivileges() {
  if (!mutate) return { ok: true, message: "Mutation disabled." };
  if (platform === "win32") {
    const probe = spawnSync("net", ["session"], { encoding: "utf8", timeout: 5000 });
    return {
      ok: probe.status === 0,
      message: probe.status === 0 ? "Windows administrator privileges available." : "Run this validator from an elevated Administrator terminal.",
    };
  }
  if (typeof process.getuid === "function") {
    return {
      ok: process.getuid() === 0,
      message: process.getuid() === 0 ? "Root privileges available." : "Run this validator with sudo/root privileges.",
    };
  }
  return { ok: false, message: "Unable to determine mutation privileges on this platform." };
}

function helperFileCheck(helper) {
  if (commandExists("file")) {
    return { name: "helper-file", ...run("file", [helper], 5000) };
  }
  const stat = fs.statSync(helper);
  return {
    name: "helper-file",
    ok: stat.size > 0,
    status: 0,
    stdout: `file command unavailable; helper exists with ${stat.size} bytes`,
    stderr: "",
    error: "",
  };
}

function helperFreshCheck(helper) {
  const sourceMtime = newestSourceMtime();
  const helperMtime = mtimeMs(helper);
  const fresh = sourceMtime > 0 && helperMtime >= sourceMtime;
  return {
    name: "helper-fresh",
    ok: fresh,
    message: fresh ? "Helper is newer than key source files." : "Helper is missing or older than key source files.",
    helperMtime,
    sourceMtime,
  };
}

function sha256File(file) {
  try {
    return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  } catch {
    return "";
  }
}

function helperHashCheck(helper) {
  const sha256 = sha256File(helper);
  return {
    name: "helper-sha256",
    ok: /^[a-f0-9]{64}$/.test(sha256),
    sha256,
    message: sha256 ? "Helper SHA-256 recorded." : "Unable to calculate helper SHA-256.",
  };
}

function runStatusCheck(helper, name, expected) {
  const attempts = [];
  const deadline = Date.now() + 10000;
  let last = null;
  do {
    const result = run(helper, ["status"], 10000);
    const stdout = result.stdout.toLowerCase();
    const installed = stdout.includes("service is installed") && !stdout.includes("service is not installed");
    const running = stdout.includes("service is running") && !stdout.includes("service is not running");
    let semanticOK = true;
    if (expected.installed !== undefined) semanticOK = semanticOK && installed === expected.installed;
    if (expected.running !== undefined) semanticOK = semanticOK && running === expected.running;
    last = {
      name,
      ...result,
      ok: result.ok && semanticOK,
      expected,
      observed: { installed, running },
    };
    attempts.push({ ok: last.ok, observed: last.observed, stdout: result.stdout });
    if (last.ok) break;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
  } while (Date.now() < deadline);
  return { ...last, attempts };
}

const helper = findHelper();
const evidence = {
  schema: "sandfox-rover-target-v1",
  platform,
  arch: os.arch(),
  mutate,
  helper,
  checks: [],
};

function emitEvidence(evidence) {
  const json = JSON.stringify(evidence, null, 2);
  const out = process.env.SANDFOX_VALIDATE_EVIDENCE_OUT;
  if (out) {
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, `${json}\n`);
    console.log(`Wrote evidence to ${out}`);
  } else {
    console.log(json);
  }
}

if (!helper) {
  evidence.checks.push({
    name: "helper-found",
    ok: false,
    message: `No helper found in: ${candidateHelpers().join(", ")}`,
  });
} else {
  evidence.checks.push({ name: "helper-found", ok: true, message: helper });
  evidence.checks.push(helperFileCheck(helper));
  evidence.checks.push(helperFreshCheck(helper));
  evidence.checks.push(helperHashCheck(helper));
  evidence.checks.push({ name: "helper-help", ...run(helper, ["help"], 10000) });
  evidence.checks.push({ name: "helper-status-before", ...run(helper, ["status"], 10000) });
  if (mutate) {
    const privileges = hasMutationPrivileges();
    evidence.checks.push({ name: "mutation-privileges", ok: privileges.ok, message: privileges.message });
    if (privileges.ok) {
      const lifecycle = [
        ["helper-install", "install"],
        ["helper-status-after-install", "status", { installed: true, running: true }],
        ["helper-stop", "stop"],
        ["helper-status-after-stop", "status", { installed: true, running: false }],
        ["helper-start", "start"],
        ["helper-status-after-start", "status", { installed: true, running: true }],
        ["helper-uninstall", "uninstall"],
        ["helper-status-after-uninstall", "status", { installed: false, running: false }],
      ];
      for (const [name, action, expected] of lifecycle) {
        if (action === "status") {
          evidence.checks.push(runStatusCheck(helper, name, expected));
        } else {
          evidence.checks.push({ name, ...run(helper, [action], 60000) });
        }
      }
    }
  } else {
    evidence.checks.push({
      name: "mutating-service-cycle",
      ok: true,
      skipped: true,
      message: "Skipped. Set SANDFOX_VALIDATE_SERVICE_MUTATION=1 on a target host to run install/status/stop/start/uninstall.",
    });
  }
}

emitEvidence(evidence);

const hardFailures = evidence.checks.filter((check) => check.name !== "helper-status-before" && check.name !== "mutating-service-cycle" && check.ok === false);
if (hardFailures.length) {
  process.exit(1);
}
if (!mutate) {
  process.exit(0);
}
const cycleFailures = evidence.checks.filter((check) => check.ok === false);
if (cycleFailures.length) {
  process.exit(1);
}
