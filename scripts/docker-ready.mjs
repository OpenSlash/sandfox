#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const timeoutMs = Number(process.env.DOCKER_READY_TIMEOUT_MS || 15000);

function dockerInfo(env) {
  return new Promise((resolve) => {
    const child = spawn("docker", ["info"], {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      resolve({ ok: false, timedOut: true, output });
    }, timeoutMs);
    child.stdout.on("data", (chunk) => {
      output += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      output += chunk.toString();
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({ ok: false, timedOut: false, output: error.message });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ ok: code === 0, timedOut: false, output });
    });
  });
}

const candidates = [{ name: "default context", env: {} }];
const desktopSocket = path.join(os.homedir(), ".docker", "run", "docker.sock");
if (fs.existsSync(desktopSocket)) {
  candidates.push({ name: "Docker Desktop socket", env: { DOCKER_HOST: `unix://${desktopSocket}` } });
}

let failures = [];
for (const candidate of candidates) {
  const result = await dockerInfo(candidate.env);
  if (result.ok) {
    console.log(`Docker is ready via ${candidate.name}`);
    process.exit(0);
  }
  const reason = result.timedOut ? `timed out after ${timeoutMs}ms` : "failed";
  failures.push(`${candidate.name}: ${reason}`);
}

console.error(`Docker is not ready: ${failures.join("; ")}`);
process.exit(1);
