// 게이트(checkTarget/classifyDecision) 회귀 테스트.
// 요구 케이스: 정상 GO / 해시 조작 REVISE / 인용 조작(fabricated) REVISE / 대역 밖 STOP /
//             CP949 자산 GO / confirmed 자가 승격 REVISE.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkTarget, classifyDecision } from "../scripts/lib/checks.mjs";
import { sha256Hex, makeRoot, cleanup, validTarget } from "./helpers.mjs";

function verdict(root, host) {
  return classifyDecision(checkTarget(root, host));
}

test("정상 설정은 GO", () => {
  const { host, files } = validTarget();
  const root = makeRoot({ host, files });
  try {
    assert.equal(verdict(root, host), "GO");
  } finally {
    cleanup(root);
  }
});

test("asset_sha256 조작(재계산 불일치)은 REVISE", () => {
  const { host, files } = validTarget();
  const root = makeRoot({ host, files });
  try {
    const fp = joinT(root, host, "findings.json");
    const doc = JSON.parse(read(fp));
    doc.findings[0].asset_sha256 = "0".repeat(64);
    write(fp, JSON.stringify(doc));
    const issues = checkTarget(root, host);
    assert.equal(classifyDecision(issues), "REVISE");
    assert.ok(issues.some((i) => /fabricated/.test(i)), "해시 조작은 fabricated 로 잡혀야 함");
  } finally {
    cleanup(root);
  }
});

test("evidence_quote 조작(파일에 없는 인용)은 REVISE — fabricated", () => {
  const { host, files } = validTarget();
  const root = makeRoot({ host, files });
  try {
    const fp = joinT(root, host, "findings.json");
    const doc = JSON.parse(read(fp));
    doc.findings[0].evidence_quote = "MakeUpProduct 99.9.9";
    write(fp, JSON.stringify(doc));
    const issues = checkTarget(root, host);
    assert.equal(classifyDecision(issues), "REVISE");
    assert.ok(issues.some((i) => /fabricated/.test(i)), "지어낸 인용은 fabricated 로 잡혀야 함");
  } finally {
    cleanup(root);
  }
});

test("대역 밖 IP 타깃은 STOP", () => {
  const { files } = validTarget({ host: "192.168.50.7" });
  const root = makeRoot({ host: "192.168.50.7", files });
  try {
    const issues = checkTarget(root, "192.168.50.7");
    assert.equal(classifyDecision(issues), "STOP");
    assert.ok(issues.some((i) => i.startsWith("STOP scope.md")), "STOP 사유가 명시되어야 함");
  } finally {
    cleanup(root);
  }
});

test("CP949 인코딩 원본 자산도 바이트 대조로 GO", () => {
  // 한글 주석이 CP949 로 인코딩된 JS — ASCII 배너는 CP949 에서도 ASCII 바이트로 남는다.
  // CP949 바이트는 파이썬으로 미리 계산해 고정(Node 는 cp949 인코딩 미지원).
  const host = "10.10.110.9";
  const cp949 = Buffer.from(
    "2f2a20bec8b3e7c7cfbcbcbfe420c1a4c2fb20c7cfb3d7bdba20c5d7bdbac6ae202a2f0a6a5175657279204a617661536372697074204c6962726172792076332e362e300a",
    "hex"
  );
  const sha = sha256Hex(cp949);
  const files = {
    "captures/raw/01_cp949.js": cp949,
    "captures/manifest.json": JSON.stringify({ target: host, assets: [{ asset_id: "AST-001",
      asset_kind: "js", raw_ref: "targets/" + host + "/captures/raw/01_cp949.js", asset_sha256: sha }] }),
    "findings.json": JSON.stringify({ target: host, findings: [{
      finding_id: "FND-001", asset_kind: "js", product: "jQuery", version: "3.6.0",
      version_bound: "UNSET", provenance: "confirmed",
      evidence_path: "targets/" + host + "/captures/raw/01_cp949.js",
      evidence_quote: "jQuery JavaScript Library v3.6.0",
      asset_sha256: sha, reasoning: "cp949 test", verified_by: ["fingerprint.py:jquery-version-banner"],
      report_eligible: false }], unmatched: [] }),
  };
  const root = makeRoot({ host, files });
  try {
    assert.equal(verdict(root, host), "GO");
  } finally {
    cleanup(root);
  }
});

test("confirmed 인데 결정론적 verified_by 없으면 REVISE (AI 자가 승격 금지)", () => {
  const { host, files } = validTarget();
  const root = makeRoot({ host, files });
  try {
    const fp = joinT(root, host, "findings.json");
    const doc = JSON.parse(read(fp));
    doc.findings[0].verified_by = ["ai-thought-this"];
    write(fp, JSON.stringify(doc));
    const issues = checkTarget(root, host);
    assert.equal(classifyDecision(issues), "REVISE");
    assert.ok(issues.some((i) => /자가 승격/.test(i)));
  } finally {
    cleanup(root);
  }
});

test("unknown 명시 발견이 없으면 REVISE, 있으면 GO", () => {
  const { host, files } = validTarget();
  const root = makeRoot({ host, files });
  try {
    const fp = joinT(root, host, "findings.json");
    const doc = JSON.parse(read(fp));
    doc.findings = [];
    write(fp, JSON.stringify(doc));
    assert.equal(classifyDecision(checkTarget(root, host)), "REVISE");
  } finally {
    cleanup(root);
  }
});

import { join, dirname } from "node:path";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
const __dirname = dirname(fileURLToPath(import.meta.url));
function joinT(root, host, rel) {
  return join(root, "targets", host, rel);
}
function read(p) {
  return readFileSync(p, "utf8");
}
function write(p, s) {
  writeFileSync(p, s, "utf8");
}
