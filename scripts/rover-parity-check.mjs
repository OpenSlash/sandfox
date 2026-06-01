#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const roverRoot = process.env.ROVER_SOURCE || "/tmp/rover-source";

function read(file) {
  return fs.readFileSync(file, "utf8");
}

function requireFile(file) {
  if (!fs.existsSync(file)) {
    throw new Error(`missing file: ${file}`);
  }
  return file;
}

function gitRef(repo) {
  const result = spawnSync("git", ["-C", repo, "rev-parse", "HEAD"], { encoding: "utf8" });
  return result.status === 0 ? result.stdout.trim() : "unknown";
}

function pascal(value) {
  return value.replace(/(^|[-_:])(\w)/g, (_match, _prefix, char) => char.toUpperCase());
}

function normalizeNodeType(value) {
  const lower = value.toLowerCase();
  if (lower === "shadowsocks") return "ss";
  if (lower === "socks") return "socks5";
  if (lower === "hy2") return "hysteria2";
  return lower;
}

function extractQuotedValues(value) {
  return [...value.matchAll(/"([^"]+)"|'([^']+)'/g)].map((match) => match[1] || match[2]);
}

function extractRoverMethods(preload) {
  const methods = [];
  const pattern = /\b([A-Za-z]\w*)\s*:\s*\([^)]*\)\s*=>\s*ipcRenderer\.invoke\('([^']+)'/g;
  for (const match of preload.matchAll(pattern)) {
    methods.push({ name: match[1], channel: match[2] });
  }
  return methods;
}

function extractWailsMethods(bindings) {
  return new Set([...bindings.matchAll(/export function ([A-Za-z]\w*)\(/g)].map((match) => match[1]));
}

function extractRoverNodeTypes(singbox) {
  const mapMatch = singbox.match(/CLASH_TYPE_SINGBOX_MAP[\s\S]*?=\s*\{([\s\S]*?)\};/);
  if (!mapMatch) return new Set();
  return new Set([...mapMatch[1].matchAll(/^\s*([A-Za-z0-9_-]+)\s*:/gm)].map((match) => normalizeNodeType(match[1])));
}

function extractSandfoxNodeTypes(service) {
  const fnMatch = service.match(/func fallbackNodeType\(value string\) string \{[\s\S]*?\n\}/);
  if (!fnMatch) return new Set();
  const types = new Set();
  for (const line of fnMatch[0].split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("case ")) continue;
    for (const value of extractQuotedValues(trimmed)) {
      types.add(normalizeNodeType(value));
    }
  }
  return types;
}

function extractRoverRuleTypes(singbox) {
  const fnMatch = singbox.match(/function convertClashRuleToRouteRule[\s\S]*?switch \(ruleType\) \{([\s\S]*?)\n\s*return routeRule/);
  if (!fnMatch) return new Set();
  const types = new Set(["MATCH"]);
  for (const value of extractQuotedValues(fnMatch[1])) {
    if (/^[A-Z0-9-]+$/.test(value)) types.add(value);
  }
  return types;
}

function extractSandfoxRuleTypes(service) {
  const fnMatch = service.match(/func looksLikeClashRuleType\(value string\) bool \{[\s\S]*?switch[\s\S]*?\{([\s\S]*?)default:/);
  if (!fnMatch) return new Set();
  return new Set(extractQuotedValues(fnMatch[1]).filter((value) => /^[A-Z0-9-]+$/.test(value)));
}

function extractGoHTTPPaths(source) {
  const paths = new Set();
  for (const match of source.matchAll(/mux\.Handle(?:Func)?\("([^"]+)"/g)) {
    paths.add(match[1]);
  }
  return paths;
}

function difference(required, actual) {
  return [...required].filter((value) => !actual.has(value)).sort();
}

const preloadPath = requireFile(path.join(roverRoot, "electron", "preload.ts"));
const roverSingboxPath = requireFile(path.join(roverRoot, "src", "services", "singbox.ts"));
const roverServicePath = requireFile(path.join(roverRoot, "roverservice", "main.go"));
const roverPresetRuleSetsPath = requireFile(path.join(roverRoot, "resources", "presets", "rulesets", "singbox.json"));
const roverTemplatesPath = requireFile(path.join(roverRoot, "resources", "presets", "templates.json"));
const servicePath = requireFile(path.join(root, "service.go"));
const helperPath = requireFile(path.join(root, "cmd", "roverservice", "main.go"));
const sandfoxPresetRuleSetsPath = requireFile(path.join(root, "resources", "presets", "rulesets", "singbox.json"));
const sandfoxTemplatesPath = requireFile(path.join(root, "resources", "presets", "templates.json"));
const bindingsPath = requireFile(
  fs.existsSync(path.join(root, "frontend", "bindings", "sandfox", "sandfoxservice.ts"))
    ? path.join(root, "frontend", "bindings", "sandfox", "sandfoxservice.ts")
    : path.join(root, "frontend", "bindings", "sandfox", "sandfoxservice.js"),
);

const preload = read(preloadPath);
const roverSingbox = read(roverSingboxPath);
const roverService = read(roverServicePath);
const service = read(servicePath);
const helper = read(helperPath);
const bindings = read(bindingsPath);
const roverPresetRuleSets = JSON.parse(read(roverPresetRuleSetsPath));
const sandfoxPresetRuleSets = JSON.parse(read(sandfoxPresetRuleSetsPath));
const roverTemplates = JSON.parse(read(roverTemplatesPath));
const sandfoxTemplates = JSON.parse(read(sandfoxTemplatesPath));

const roverMethods = extractRoverMethods(preload);
const wailsMethods = extractWailsMethods(bindings);
const apiMappings = roverMethods.map((method) => {
  const candidates = [
    ["name", method.name],
    ["pascalName", pascal(method.name)],
    ["channelTail", pascal(method.channel.split(":").pop() || "")],
    ["upperName", method.name[0].toUpperCase() + method.name.slice(1)],
  ];
  const hit = candidates.find(([, candidate]) => wailsMethods.has(candidate));
  return { ...method, strategy: hit?.[0] || "", mapped: hit?.[1] || "" };
});
const missingMethods = roverMethods.filter((method) => {
  const candidates = new Set([
    method.name,
    pascal(method.name),
    pascal(method.channel.split(":").pop() || ""),
    method.name[0].toUpperCase() + method.name.slice(1),
  ]);
  return ![...candidates].some((candidate) => wailsMethods.has(candidate));
});
const weakAPIMappings = apiMappings.filter((mapping) => mapping.strategy === "channelTail");

const roverNodeTypes = extractRoverNodeTypes(roverSingbox);
const sandfoxNodeTypes = extractSandfoxNodeTypes(service);
const missingNodeTypes = difference(roverNodeTypes, sandfoxNodeTypes);

const roverRuleTypes = extractRoverRuleTypes(roverSingbox);
const sandfoxRuleTypes = extractSandfoxRuleTypes(service);
const missingRuleTypes = difference(roverRuleTypes, sandfoxRuleTypes);

const roverHelperPaths = extractGoHTTPPaths(roverService);
const sandfoxHelperPaths = extractGoHTTPPaths(helper);
const missingHelperPaths = difference(roverHelperPaths, sandfoxHelperPaths);
const presetRuleSetCountMatches = Array.isArray(roverPresetRuleSets) && Array.isArray(sandfoxPresetRuleSets) && roverPresetRuleSets.length === sandfoxPresetRuleSets.length;
const roverTemplatePaths = new Set(Array.isArray(roverTemplates) ? roverTemplates.map((template) => template.path).filter(Boolean) : []);
const sandfoxTemplatePaths = new Set(Array.isArray(sandfoxTemplates) ? sandfoxTemplates.map((template) => template.path).filter(Boolean) : []);
const missingTemplatePaths = difference(roverTemplatePaths, sandfoxTemplatePaths);

console.log(`Rover API methods: ${roverMethods.length}`);
console.log(`Rover source ref: ${gitRef(roverRoot)}`);
console.log(`Sandfox Wails methods: ${wailsMethods.size}`);
console.log(`Missing API methods: ${missingMethods.length}`);
console.log(`Weak API mappings: ${weakAPIMappings.length}`);
console.log(`Rover node types: ${[...roverNodeTypes].sort().join(", ")}`);
console.log(`Missing node types: ${missingNodeTypes.length ? missingNodeTypes.join(", ") : "none"}`);
console.log(`Rover Clash rule types: ${[...roverRuleTypes].sort().join(", ")}`);
console.log(`Missing Clash rule types: ${missingRuleTypes.length ? missingRuleTypes.join(", ") : "none"}`);
console.log(`RoverService endpoints: ${[...roverHelperPaths].sort().join(", ")}`);
console.log(`Missing RoverService endpoints: ${missingHelperPaths.length ? missingHelperPaths.join(", ") : "none"}`);
console.log(`Rover preset rule sets: ${Array.isArray(roverPresetRuleSets) ? roverPresetRuleSets.length : "invalid"}`);
console.log(`Sandfox embedded preset rule sets: ${Array.isArray(sandfoxPresetRuleSets) ? sandfoxPresetRuleSets.length : "invalid"}`);
console.log(`Rover templates: ${Array.isArray(roverTemplates) ? roverTemplates.length : "invalid"}`);
console.log(`Missing Rover templates: ${missingTemplatePaths.length ? missingTemplatePaths.join(", ") : "none"}`);

if (missingMethods.length || weakAPIMappings.length || missingNodeTypes.length || missingRuleTypes.length || missingHelperPaths.length || !presetRuleSetCountMatches || missingTemplatePaths.length) {
  if (missingMethods.length) {
    console.error("Missing API details:");
    for (const method of missingMethods) {
      console.error(`- ${method.name}:${method.channel}`);
    }
  }
  if (weakAPIMappings.length) {
    console.error("Weak API mappings that only matched generic IPC channel tails:");
    for (const mapping of weakAPIMappings) {
      console.error(`- ${mapping.name}:${mapping.channel} -> ${mapping.mapped}`);
    }
  }
  if (missingHelperPaths.length) {
    console.error("Missing RoverService endpoint details:");
    for (const endpoint of missingHelperPaths) {
      console.error(`- ${endpoint}`);
    }
  }
  if (!presetRuleSetCountMatches) {
    console.error("Preset rule set count does not match Rover.");
  }
  if (missingTemplatePaths.length) {
    console.error("Missing Rover template details:");
    for (const templatePath of missingTemplatePaths) {
      console.error(`- ${templatePath}`);
    }
  }
  process.exit(1);
}
