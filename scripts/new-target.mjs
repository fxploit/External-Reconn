#!/usr/bin/env node
// 새 타깃 워크스페이스를 템플릿으로 생성한다.
// Usage: node scripts/new-target.mjs <host>
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { existsSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, "..");

const host = process.argv[2];
if (!host || /[^A-Za-z0-9._:-]/.test(host)) {
  console.error("Usage: node scripts/new-target.mjs <host>  (영숫자/.:_- 만 허용)");
  process.exit(1);
}

const base = resolve(root, "targets", host);
if (existsSync(base)) {
  console.error("이미 존재합니다: targets/" + host);
  process.exit(1);
}
for (const d of ["captures/raw", "captures/normalized", "captures/observation"]) {
  mkdirSync(resolve(base, d), { recursive: true });
}

const findingTpl = readFileSync(resolve(root, "harness/templates/finding.json"), "utf8").replace(
  '"target": "UNSET"',
  '"target": "' + host + '"'
);
writeFileSync(resolve(base, "findings.json"), findingTpl);

const reportTpl = readFileSync(resolve(root, "harness/templates/report.md"), "utf8").replaceAll(
  "<TARGET>",
  host
);
writeFileSync(resolve(base, "report.md"), reportTpl);
writeFileSync(resolve(base, "captures", ".gitkeep"), "");

console.log("created targets/" + host + "/  (findings.json, report.md, captures/)");
console.log("다음: python scripts/collect_web.py <url> --target " + host);
