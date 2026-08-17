// 테스트 헬퍼 — 임시 targets/ 워크스페이스(루트)를 만들어 게이트 로직을 격리 테스트한다.
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";

export function sha256Hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

export function isHashLike(v) {
  return typeof v === "string" && /^[a-f0-9]{64}$/i.test(v);
}

export function makeRoot(t) {
  const root = mkdtempSync(join(tmpdir(), "recon-gate-test-"));
  writeFileSync(join(root, "scope.md"), t.scope ?? "허용 대역: 10.10.110.0/24\n");
  const base = join(root, "targets", t.host);
  for (const rel of Object.keys(t.files || {})) {
    const p = join(base, rel);
    mkdirSync(join(p, ".."), { recursive: true });
    const v = t.files[rel];
    writeFileSync(p, typeof v === "string" ? Buffer.from(v, "utf8") : v);
  }
  return root;
}

export function cleanup(root) {
  rmSync(root, { recursive: true, force: true });
}

// 유효한 GO 설정: scope 안 IP, 실재 파일+해시+인용 바인딩, 결정론적 verified_by.
export function validTarget(overrides = {}) {
  const host = overrides.host ?? "10.10.110.5";
  const js = Buffer.from('/* banner */\njQuery JavaScript Library v3.6.0\n');
  const sha = sha256Hex(js);
  const files = {
    "captures/raw/01_test.js": js,
    "captures/manifest.json": JSON.stringify({
      target: host,
      assets: [{ asset_id: "AST-001", asset_kind: "js", source_url: "http://" + host + "/a.js",
        raw_ref: "targets/" + host + "/captures/raw/01_test.js", asset_sha256: sha }],
    }),
    "findings.json": JSON.stringify({
      target: host,
      findings: [{
        finding_id: "FND-001",
        asset_kind: "js",
        product: "jQuery",
        version: "3.6.0",
        version_bound: "UNSET",
        provenance: "confirmed",
        evidence_path: "targets/" + host + "/captures/raw/01_test.js",
        evidence_quote: "jQuery JavaScript Library v3.6.0",
        asset_sha256: sha,
        reasoning: "test fixture",
        verified_by: ["fingerprint.py:jquery-version-banner"],
        report_eligible: false,
      }],
      unmatched: [],
    }),
  };
  return { host, files };
}
