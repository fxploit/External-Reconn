#!/usr/bin/env node
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { checkTarget, classifyDecision } from "./lib/checks.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, "..");

const hint = process.argv[2] || null;
const issues = checkTarget(root, hint);
const decision = classifyDecision(issues);

const label = hint ? "TARGET=" + hint + " " : "";
console.log(label + "DECISION=" + decision);
if (issues.length) {
  console.log("");
  for (const issue of issues) console.log("  - " + issue);
}
process.exit(decision === "GO" ? 0 : 1);
