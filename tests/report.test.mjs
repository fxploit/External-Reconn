import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { resolve, join } from "node:path";

const root = resolve(import.meta.dirname, "..");

test("T31/T32: engagement log ref와 report.md를 데이터로 조립", () => {
  const host = `report-${Date.now()}`;
  const base = join(root, "targets", host);
  mkdirSync(join(base, "captures", "observation", "run-log"), { recursive: true });
  try {
    const raw = Buffer.from("evidence-value\n");
    const rawPath = join(base, "captures", "observation", "evidence.txt");
    writeFileSync(rawPath, raw);
    writeFileSync(join(base, "captures", "manifest.json"), JSON.stringify({
      target: host, entry_url: "http://example.test/", produced_by: "test",
      runtime_image_digest: "sha256:test",
      assets: [],
    }, null, 2));
    writeFileSync(join(base, "findings.json"), JSON.stringify({ target: host, findings: [{
      finding_id: "FND-001", product: "test-product", version: "1.0.0", version_bound: "UNSET",
      provenance: "confirmed", evidence_path: `targets/${host}/captures/observation/evidence.txt`,
      evidence_quote: "evidence-value", asset_sha256: "placeholder", discovered_at: "2026-01-01T00:00:00Z",
      verified_by: ["fingerprint.py:test"], report_eligible: false,
    }], unmatched: [] }, null, 2));
    writeFileSync(join(base, "engagement-log.jsonl"), JSON.stringify({
      event: "fingerprint", timestamp: "2026-01-01T00:00:00Z", findings_ref: `targets/${host}/findings.json`,
    }) + "\n");
    writeFileSync(join(base, "captures/observation/run-log/command-log.jsonl"), JSON.stringify({
      timestamp_start: "2026-01-01T00:00:00Z", command: ["python", "test"], exit_code: 0,
      stdout_ref: `targets/${host}/captures/observation/run-log/x.out.txt`,
      stderr_ref: `targets/${host}/captures/observation/run-log/x.err.txt`,
      stdout_sha256: "out", stderr_sha256: "err",
    }) + "\n");
    const result = spawnSync("python", ["scripts/build_report.py", host], { cwd: root, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const report = readFileSync(join(base, "report.md"), "utf8");
    assert.match(report, /test-product/);
    assert.match(report, /evidence-value/);
    assert.match(report, /fingerprint/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
