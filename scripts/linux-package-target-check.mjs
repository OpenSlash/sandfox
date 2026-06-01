#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const mutate = process.env.SANDFOX_VALIDATE_LINUX_PACKAGE_MUTATION === "1";
const packageCommand = process.env.SANDFOX_LINUX_PACKAGE_COMMAND
  || (process.env.SANDFOX_LINUX_PACKAGE_DOCKER === "1"
    ? "sh scripts/linux-package-docker-target.sh"
    : "wails3 task linux:package");

function runShell(command, timeout = 600000) {
  const result = spawnSync(command, {
    cwd: root,
    shell: true,
    encoding: "utf8",
    timeout,
  });
  return {
    command,
    ok: result.status === 0,
    status: result.status,
    stdout: (result.stdout || "").trim(),
    stderr: (result.stderr || "").trim(),
    error: result.error?.message || "",
  };
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

function sha256File(file) {
  try {
    return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  } catch {
    return "";
  }
}

function listArtifacts() {
  const bin = path.join(root, "bin");
  if (!fs.existsSync(bin)) return [];
  return fs.readdirSync(bin)
    .filter((name) => /\.(AppImage|deb|rpm|pkg\.tar\.\w+)$/i.test(name))
    .map((name) => {
      const fullPath = path.join(bin, name);
      const stat = fs.statSync(fullPath);
      return { name, path: fullPath, size: stat.size, mtimeMs: stat.mtimeMs, sha256: sha256File(fullPath) };
    });
}

const packagingSourceMtime = newestMtime([
  "service.go",
  "cmd/roverservice/main.go",
  "rover_service_dial_unix.go",
  "rover_service_dial_windows.go",
  "frontend/src/App.tsx",
]);

const evidence = {
  schema: "sandfox-rover-target-v1",
  platform: process.platform,
  arch: os.arch(),
  mutate,
  packageCommand,
  packagingSourceMtime,
  checks: [],
  artifacts: [],
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

if (mutate) {
  evidence.checks.push({ name: "linux-package-command", ...runShell(packageCommand) });
} else {
  evidence.checks.push({
    name: "linux-package-command",
    ok: false,
    message: "Skipped. Set SANDFOX_VALIDATE_LINUX_PACKAGE_MUTATION=1 on a Linux/Docker target to run the package command.",
  });
}

evidence.artifacts = listArtifacts();
const hasAppImage = evidence.artifacts.some((artifact) => artifact.name.endsWith(".AppImage") && artifact.size > 0);
const hasDeb = evidence.artifacts.some((artifact) => artifact.name.endsWith(".deb") && artifact.size > 0);
const hasRpm = evidence.artifacts.some((artifact) => artifact.name.endsWith(".rpm") && artifact.size > 0);
const hasArch = evidence.artifacts.some((artifact) => /\.pkg\.tar\.\w+$/i.test(artifact.name) && artifact.size > 0);
const artifactsFresh = evidence.artifacts.length > 0 && evidence.artifacts.every((artifact) => artifact.mtimeMs >= packagingSourceMtime);
const artifactsHashed = evidence.artifacts.length > 0 && evidence.artifacts.every((artifact) => /^[a-f0-9]{64}$/.test(artifact.sha256));
evidence.checks.push({ name: "linux-appimage-artifact", ok: hasAppImage, message: hasAppImage ? "AppImage artifact found." : "No AppImage artifact found." });
evidence.checks.push({ name: "linux-deb-artifact", ok: hasDeb, message: hasDeb ? "DEB artifact found." : "No DEB artifact found." });
evidence.checks.push({ name: "linux-rpm-artifact", ok: hasRpm, message: hasRpm ? "RPM artifact found." : "No RPM artifact found." });
evidence.checks.push({ name: "linux-aur-artifact", ok: hasArch, message: hasArch ? "Arch Linux package artifact found." : "No Arch Linux package artifact found." });
evidence.checks.push({ name: "linux-artifacts-fresh", ok: artifactsFresh, message: artifactsFresh ? "Linux package artifacts are newer than key source files." : "Linux package artifacts are missing or older than key source files." });
evidence.checks.push({ name: "linux-artifact-hashes", ok: artifactsHashed, message: artifactsHashed ? "Linux package artifact SHA-256 hashes recorded." : "Linux package artifact SHA-256 hashes are missing." });

emitEvidence(evidence);

const failures = evidence.checks.filter((check) => check.ok === false);
if (mutate && failures.length) {
  process.exit(1);
}
if (!mutate && failures.some((check) => check.name !== "linux-package-command")) {
  process.exit(1);
}
