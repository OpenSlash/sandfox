#!/usr/bin/env node

const evidenceDir = process.env.SANDFOX_AUDIT_EVIDENCE_DIR || "/tmp/sandfox-rover-evidence";

const blocks = [
  {
    title: "macOS privileged RoverService lifecycle",
    shell: "sh",
    command: `mkdir -p "${evidenceDir}"
export PATH="$HOME/go/bin:$PATH"
sudo env \\
  SANDFOX_VALIDATE_SERVICE_MUTATION=1 \\
  SANDFOX_VALIDATE_EVIDENCE_OUT="${evidenceDir}/macos-service.json" \\
  PATH="$PATH" \\
  wails3 task validate:roverservice`,
  },
  {
    title: "Windows Administrator RoverService lifecycle",
    shell: "powershell",
    command: `$env:SANDFOX_VALIDATE_SERVICE_MUTATION="1"
$env:SANDFOX_VALIDATE_EVIDENCE_OUT="C:\\sandfox-rover-evidence\\windows-service.json"
$env:Path="$env:USERPROFILE\\go\\bin;$env:Path"
wails3 task validate:roverservice`,
  },
  {
    title: "Linux systemd RoverService lifecycle",
    shell: "sh",
    command: `mkdir -p "${evidenceDir}"
export PATH="$HOME/go/bin:$PATH"
sudo env \\
  SANDFOX_VALIDATE_SERVICE_MUTATION=1 \\
  SANDFOX_VALIDATE_EVIDENCE_OUT="${evidenceDir}/linux-service.json" \\
  PATH="$PATH" \\
  wails3 task validate:roverservice`,
  },
  {
    title: "Linux full package artifacts",
    shell: "sh",
    command: `mkdir -p "${evidenceDir}"
export PATH="$HOME/go/bin:$PATH"
SANDFOX_VALIDATE_LINUX_PACKAGE_MUTATION=1 \\
SANDFOX_VALIDATE_EVIDENCE_OUT="${evidenceDir}/linux-package.json" \\
wails3 task validate:linux-package`,
  },
  {
    title: "Linux full package artifacts via Docker target",
    shell: "sh",
    command: `mkdir -p "${evidenceDir}"
export PATH="$HOME/go/bin:$PATH"
# Optional: pre-place AppImage tooling in build/linux/appimage/cache to avoid GitHub download flakiness.
SANDFOX_VALIDATE_LINUX_PACKAGE_MUTATION=1 \\
SANDFOX_LINUX_PACKAGE_DOCKER=1 \\
SANDFOX_VALIDATE_EVIDENCE_OUT="${evidenceDir}/linux-package.json" \\
wails3 task validate:linux-package`,
  },
  {
    title: "Final completion audit",
    shell: "sh",
    command: `export PATH="$HOME/go/bin:$PATH"
SANDFOX_AUDIT_EVIDENCE_DIR="${evidenceDir}" wails3 task audit:rover`,
  },
];

console.log("Rover target evidence commands");
console.log("==============================");
console.log(`Evidence directory: ${evidenceDir}`);
console.log("");
for (const block of blocks) {
  console.log(`## ${block.title}`);
  console.log(`\`\`\`${block.shell}`);
  console.log(block.command);
  console.log("```");
  console.log("");
}
