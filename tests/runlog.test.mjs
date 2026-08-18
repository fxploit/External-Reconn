import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";

const root = resolve(import.meta.dirname, "..");

test("T30: recon.mjs host fallback 실행 저널과 stdout/stderr sha 보존", () => {
  const host = `runlog-${Date.now()}`;
  const target = join(root, "targets", host);
  mkdirSync(target, { recursive: true });
  try {
    const result = spawnSync("node", ["scripts/recon.mjs", "--target", host, "node", "-e",
      "process.stdout.write('journal-out'); process.stderr.write('journal-err')"], {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env, RECON_FORCE_LOCAL: "1" },
    });
    assert.equal(result.status, 0, result.stderr);
    const logDir = join(target, "captures", "observation", "run-log");
    const journal = join(logDir, "command-log.jsonl");
    assert.ok(existsSync(journal), "command-log.jsonl 필요");
    const record = JSON.parse(readFileSync(journal, "utf8").trim().split("\n").at(-1));
    assert.equal(record.environment, "host-fallback");
    assert.equal(record.exit_code, 0);
    assert.equal(record.runtime_image_digest, null);
    const out = join(root, record.stdout_ref);
    const err = join(root, record.stderr_ref);
    assert.equal(readFileSync(out, "utf8"), "journal-out");
    assert.equal(readFileSync(err, "utf8"), "journal-err");
    assert.equal(record.stdout_sha256, createHash("sha256").update(readFileSync(out)).digest("hex"));
    assert.equal(record.stderr_sha256, createHash("sha256").update(readFileSync(err)).digest("hex"));
  } finally {
    rmSync(target, { recursive: true, force: true });
  }
});
