#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const evidenceDir = process.env.SANDFOX_AUDIT_EVIDENCE_DIR || "/tmp/sandfox-rover-evidence";
const output = process.env.SANDFOX_PENDING_EVIDENCE_OUT || path.join(evidenceDir, "pending-target-evidence.json");

const required = [
  {
    gate: "macos-privileged-service-real-run",
    file: "macos-service.json",
    blocker: "requires explicit authorization and sudo password on macOS",
  },
  {
    gate: "windows-service-real-run",
    file: "windows-service.json",
    blocker: "requires Windows Administrator/UAC target host",
  },
  {
    gate: "linux-systemd-real-run",
    file: "linux-service.json",
    blocker: "requires Linux systemd target host with sudo/root",
  },
  {
    gate: "linux-full-package-environment",
    file: "linux-package.json",
    blocker: "requires working Docker or Linux package environment",
  },
];

const entries = required.map((item) => {
  const filePath = path.join(evidenceDir, item.file);
  return {
    ...item,
    path: filePath,
    present: fs.existsSync(filePath),
  };
});

const data = {
  schema: "sandfox-rover-pending-evidence-v1",
  evidenceDir,
  generatedAt: new Date().toISOString(),
  missingCount: entries.filter((item) => !item.present).length,
  requiredCount: entries.length,
  missing: entries.filter((item) => !item.present),
  present: entries.filter((item) => item.present),
};

fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, `${JSON.stringify(data, null, 2)}\n`);
console.log(`Wrote pending evidence manifest to ${output}`);
