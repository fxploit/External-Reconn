// 파이프라인 통합 회귀 테스트 — 실제 스크립트(fingerprint.py / merge_fallback.py / second_pass.py
// / extract_assets.py / deobfuscate.py)와 실제 게이트를 저장소 targets/ 에서 end-to-end 로 실행한다.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";
import { createHash } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, "..");
const PY = process.env.PYTHON || "python";

function sha256Hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
}
function run(cmd, args) {
  return spawnSync(cmd, args, { cwd: root, encoding: "utf8" });
}
function gate(host) {
  const r = run("node", ["scripts/check-recon.mjs", host]);
  const m = r.stdout.match(/DECISION=(\w+)/);
  return { decision: m ? m[1] : "?", out: r.stdout };
}
function writeJson(p, obj) {
  writeFileSync(p, JSON.stringify(obj, null, 2), "utf8");
}
function readJson(p) {
  return JSON.parse(readFileSync(p, "utf8"));
}

function makeTarget(host, rawFiles) {
  const base = join(root, "targets", host);
  rmSync(base, { recursive: true, force: true });
  mkdirSync(join(base, "captures", "raw"), { recursive: true });
  mkdirSync(join(base, "captures", "observation"), { recursive: true });
  const assets = [];
  let i = 0;
  for (const [name, data] of Object.entries(rawFiles)) {
    const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
    const rel = `targets/${host}/captures/raw/${name}`;
    writeFileSync(join(root, rel), buf);
    assets.push({ asset_id: `AST-${String(i).padStart(3, "0")}`, source_url: "http://x/" + name,
      asset_kind: name.endsWith(".js") ? "js" : name.endsWith(".css") ? "css"
        : name.endsWith(".html") ? "html"
        : name.endsWith(".map") ? "sourcemap"
        : name.startsWith("__headers__") ? "header"
        : name.startsWith("__cookies__") ? "cookie" : "other",
      http_status: 200, content_type: "text/plain", raw_ref: rel, asset_sha256: sha256Hex(buf) });
    i++;
  }
  writeJson(join(base, "captures", "manifest.json"),
    { target: host, entry_url: "http://x/", collected_at: new Date().toISOString(), assets });
  return base;
}

test("fingerprint.py → 게이트 GO (결정론 매칭·unknown 명시 발견)", () => {
  const host = "it-" + Date.now();
  try {
    makeTarget(host, {
      "01_app.js": "/*! jQuery JavaScript Library v3.6.0 */\ncreateRoot(document.getElementById('root'));\n",
      "02_style.css": "body { color: #333; }",
    });
    const fp = run(PY, ["scripts/fingerprint.py", host]);
    assert.equal(fp.status, 0, fp.stderr || fp.stdout);
    const doc = readJson(join(root, "targets", host, "findings.json"));
    assert.ok(doc.findings.some((f) => f.provenance === "confirmed" && f.product === "jQuery"), "jQuery confirmed 필요");
    assert.ok(doc.findings.some((f) => f.product === "React" && f.provenance === "inferred"), "React inferred 필요");
    assert.ok(doc.findings.some((f) => f.provenance === "unknown"), "미매칭 css 는 unknown 명시 발견이어야 함");
    assert.equal(gate(host).decision, "GO", gate(host).out);
  } finally {
    rmSync(join(root, "targets", host), { recursive: true, force: true });
  }
});

test("CP949 원본 자산 파이프라인 → fingerprint 매칭 + 게이트 GO", () => {
  const host = "it-" + Date.now();
  try {
    const cp949 = Buffer.from(
      "2f2a20bec8b3e7c7cfbcbcbfe420c1a4c2fb20c7cfb3d7bdba20c5d7bdbac6ae202a2f0a6a5175657279204a617661536372697074204c6962726172792076332e362e300a",
      "hex"
    );
    makeTarget(host, { "01_cp949.js": cp949 });
    const fp = run(PY, ["scripts/fingerprint.py", host]);
    assert.equal(fp.status, 0, fp.stderr || fp.stdout);
    assert.ok(readJson(join(root, "targets", host, "findings.json"))
      .findings.some((f) => f.product === "jQuery" && f.provenance === "confirmed"));
    assert.equal(gate(host).decision, "GO", gate(host).out);
  } finally {
    rmSync(join(root, "targets", host), { recursive: true, force: true });
  }
});

test("지어낸 인용(fabricated)이 findings 에 들어가면 게이트가 REVISE (안전망)", () => {
  const host = "it-" + Date.now();
  try {
    makeTarget(host, { "01_app.js": "jQuery JavaScript Library v3.6.0\n" });
    const fp = run(PY, ["scripts/fingerprint.py", host]);
    assert.equal(fp.status, 0);
    const fpath = join(root, "targets", host, "findings.json");
    const doc = readJson(fpath);
    doc.findings.push({
      finding_id: "FND-999", asset_kind: "js", product: "FakeLib", version: "9.9.9",
      version_bound: "UNSET", provenance: "confirmed",
      evidence_path: `targets/${host}/captures/raw/01_app.js`,
      evidence_quote: "FakeLib 9.9.9 does not exist in this file",
      asset_sha256: sha256Hex(Buffer.from("jQuery JavaScript Library v3.6.0\n")),
      reasoning: "fabricated", verified_by: ["second-pass:support"], report_eligible: false,
    });
    writeJson(fpath, doc);
    const g = gate(host);
    assert.equal(g.decision, "REVISE");
    assert.ok(/fabricated/.test(g.out), "REVISE 사유에 fabricated 가 있어야 함:\n" + g.out);
  } finally {
    rmSync(join(root, "targets", host), { recursive: true, force: true });
  }
});

test("second_pass: support 유지/contradict 강등 → 게이트 반영", () => {
  const host = "it-" + Date.now();
  try {
    makeTarget(host, { "01_app.js": "/*! jQuery JavaScript Library v3.6.0 */\n" });
    assert.equal(run(PY, ["scripts/fingerprint.py", host]).status, 0);
    const prep = run(PY, ["scripts/second_pass.py", host, "--prepare"]);
    assert.equal(prep.status, 0, prep.stderr || prep.stdout);
    const fpath = join(root, "targets", host, "findings.json");
    const doc = readJson(fpath);
    const conf = doc.findings.find((f) => f.provenance === "confirmed");
    assert.ok(conf, "confirmed 발견 필요");
    const vpath = join(root, "targets", host, "verdicts-tmp.json");
    writeJson(vpath, { verdicts: [{ finding_id: conf.finding_id, verdict: "contradict" }] });
    const app = run(PY, ["scripts/second_pass.py", host, "--apply", vpath]);
    assert.equal(app.status, 0, app.stderr || app.stdout);
    const after = readJson(fpath);
    const f = after.findings.find((x) => x.finding_id === conf.finding_id);
    assert.equal(f.provenance, "inferred", "contradict 시 confirmed→inferred 강등");
    assert.ok(f.verified_by.includes("second-pass:contradict"));
    assert.equal(gate(host).decision, "GO");
  } finally {
    rmSync(join(root, "targets", host), { recursive: true, force: true });
  }
});

test("T9: 헤더/쿠키가 1급 자산으로 매칭되고 게이트 GO", () => {
  const host = "it-" + Date.now();
  try {
    const headers = "Server: nginx/1.18.0 (Ubuntu)\nX-Powered-By: PHP/7.4.33\n";
    const cookies = "csrftoken=abc123; Path=/; SameSite=Lax\nsessionid=xyz; HttpOnly; Path=/\n";
    makeTarget(host, {
      "01_app.js": "/*! jQuery JavaScript Library v3.6.0 */\n",
      "__headers__.txt": headers,
      "__cookies__.txt": cookies,
    });
    const fp = run(PY, ["scripts/fingerprint.py", host]);
    assert.equal(fp.status, 0, fp.stderr || fp.stdout);
    const doc = readJson(join(root, "targets", host, "findings.json"));
    const hdr = doc.findings.find((f) => f.asset_kind === "header" && f.product === "nginx");
    assert.ok(hdr && hdr.version === "1.18.0" && hdr.provenance === "confirmed", "nginx 헤더 confirmed");
    assert.ok(doc.findings.some((f) => f.asset_kind === "header" && f.product === "PHP" && f.version === "7.4.33"));
    const dj = doc.findings.filter((f) => f.asset_kind === "cookie" && f.product === "Django");
    assert.ok(dj.length >= 2, "csrftoken/sessionid 쿠키 매칭");
    assert.ok(!doc.findings.some((f) => f.asset_kind === "cookie" && /abc123/.test(f.evidence_quote)),
      "쿠키 값 원문은 인용되지 않아야 함(마스킹)");
    assert.equal(gate(host).decision, "GO", gate(host).out);
  } finally {
    rmSync(join(root, "targets", host), { recursive: true, force: true });
  }
});

test("T11: Django admin 정적 해시 DB → 버전 confirmed", () => {
  const host = "it-" + Date.now();
  try {
    const css = readFileSync(join(root, "tests/fixtures/www/assets/vendor/django-admin-base.css"));
    makeTarget(host, { "01_base.css": css });
    const mpath = join(root, "targets", host, "captures", "manifest.json");
    const m = readJson(mpath);
    m.assets[0].source_url = `http://x/static/admin/css/base.css`;
    writeJson(mpath, m);
    const fp = run(PY, ["scripts/fingerprint.py", host]);
    assert.equal(fp.status, 0, fp.stderr || fp.stdout);
    const doc = readJson(join(root, "targets", host, "findings.json"));
    const dj = doc.findings.find((f) => f.product === "Django" && f.provenance === "confirmed");
    assert.ok(dj, "Django confirmed 필요");
    assert.equal(dj.version, "4.2.11", "base.css sha256 → Django 4.2.11");
    assert.equal(gate(host).decision, "GO", gate(host).out);
  } finally {
    rmSync(join(root, "targets", host), { recursive: true, force: true });
  }
});

test("T15: 시크릿 추출 — 존재 confirmed·원문 마스킹·게이트 GO", () => {
  const host = "it-" + Date.now();
  try {
    makeTarget(host, {
      "01_app.js": "var k = 'AKIAIOSFODNN7EXAMPLE';\nvar t = 'ghp_0123456789abcdef0123456789abcdef0123';\n",
    });
    const fp = run(PY, ["scripts/fingerprint.py", host]);
    assert.equal(fp.status, 0);
    const ex = run(PY, ["scripts/extract_assets.py", host]);
    assert.equal(ex.status, 0, ex.stderr || ex.stdout);
    const doc = readJson(join(root, "targets", host, "findings.json"));
    const secs = doc.findings.filter((f) => f.asset_kind === "secret");
    assert.ok(secs.length >= 2, "시크릿 2건 이상 필요");
    assert.ok(secs.every((s) => /\.\.\./.test(s.secret_masked) && !/AKIAIOSFODNN7EXAMPLE|ghp_01/.test(s.evidence_quote)),
      "원문은 evidence_quote 에 없고 마스킹만");
    assert.ok(secs.every((s) => s.provenance === "confirmed"), "존재 confirmed");
    assert.equal(gate(host).decision, "GO", gate(host).out);
  } finally {
    rmSync(join(root, "targets", host), { recursive: true, force: true });
  }
});

test("T18: fingerprint 멱등 병합 — 외부 발견이 재실행에도 보존", () => {
  const host = "it-" + Date.now();
  try {
    makeTarget(host, { "01_app.js": "/*! jQuery JavaScript Library v3.6.0 */\n" });
    assert.equal(run(PY, ["scripts/fingerprint.py", host]).status, 0);
    const fpath = join(root, "targets", host, "findings.json");
    const js = Buffer.from("/*! jQuery JavaScript Library v3.6.0 */\n");
    const sha = sha256Hex(js);
    let doc = readJson(fpath);
    doc.findings.push({
      finding_id: "FND-900", generated_by: "active_recon.py", asset_kind: "service",
      product: "nginx", version: "1.18.0", version_bound: "UNSET", provenance: "confirmed",
      evidence_path: `targets/${host}/captures/raw/01_app.js`, evidence_quote: "jQuery JavaScript Library v3.6.0",
      asset_sha256: sha, reasoning: "nmap test", verified_by: ["active_recon.py:nmap"], report_eligible: false,
    });
    writeJson(fpath, doc);
    assert.equal(run(PY, ["scripts/fingerprint.py", host]).status, 0);
    doc = readJson(fpath);
    assert.ok(doc.findings.some((f) => f.finding_id === "FND-900" && f.product === "nginx"),
      "active_recon 발견이 fingerprint 재실행에 보존되어야 함");
    const conf = doc.findings.find((f) => f.product === "jQuery" && f.provenance === "confirmed");
    const vpath = join(root, "targets", host, "verdicts2.json");
    writeJson(vpath, { verdicts: [{ finding_id: conf.finding_id, verdict: "contradict" }] });
    assert.equal(run(PY, ["scripts/second_pass.py", host, "--apply", vpath]).status, 0);
    assert.equal(run(PY, ["scripts/fingerprint.py", host]).status, 0);
    doc = readJson(fpath);
    const demoted = doc.findings.find((f) => f.finding_id === conf.finding_id);
    assert.equal(demoted.provenance, "inferred", "second-pass:contradict 강등이 fingerprint 재실행에도 유지");
    assert.ok(demoted.verified_by.includes("second-pass:contradict"));
    assert.equal(gate(host).decision, "GO", gate(host).out);
  } finally {
    rmSync(join(root, "targets", host), { recursive: true, force: true });
  }
});

test("T18: fallback 업그레이드 결과가 fingerprint 재실행에도 보존 + unknown 미재생성", () => {
  const host = "it-" + Date.now();
  try {
    makeTarget(host, {
      "01_app.js": "window.ACME = { name: 'acme-ui', version: '4.7.1' };\n",
      "02_style.css": "body{}\n",
    });
    assert.equal(run(PY, ["scripts/fingerprint.py", host]).status, 0);
    const fpath = join(root, "targets", host, "findings.json");
    const doc0 = readJson(fpath);
    const unmatchedId = doc0.unmatched[0].asset_id;
    const jpath = join(root, "targets", host, "judgments3.json");
    writeJson(jpath, { judgments: [{
      asset_id: unmatchedId, product: "acme-ui", version: "4.7.1", provenance: "inferred",
      evidence_quote: "name: 'acme-ui', version: '4.7.1'", reasoning: "번들 패키지 메타데이터",
    }] });
    assert.equal(run(PY, ["scripts/merge_fallback.py", host, jpath]).status, 0);
    assert.equal(run(PY, ["scripts/fingerprint.py", host]).status, 0);
    const doc = readJson(fpath);
    const acme = doc.findings.find((f) => f.product === "acme-ui");
    assert.ok(acme && acme.provenance === "inferred", "fallback 업그레이드가 fingerprint 재실행에 보존");
    assert.ok(!doc.findings.some((f) => f.product === "unidentified" && f.evidence_path === `targets/${host}/captures/raw/01_app.js`),
      "해결된 자산에 unidentified unknown 이 재생성되지 않아야 함");
    assert.ok(!doc.unmatched.some((u) => u.asset_id === unmatchedId), "unmatched 재추가 금지");
    assert.equal(gate(host).decision, "GO", gate(host).out);
  } finally {
    rmSync(join(root, "targets", host), { recursive: true, force: true });
  }
});

test("T21: 난독화 JS 디오브푸스케이션 — 숨은 엔드포인트 발견·게이트 GO", () => {
  const host = "it-" + Date.now();
  try {
    const fx = join(root, "tests/fixtures/obfuscated");
    makeTarget(host, {
      "01_eval_packed.js": readFileSync(join(fx, "eval_packed.js")),
      "02_string_array.js": readFileSync(join(fx, "string_array.js")),
      "03_base64_blob.js": readFileSync(join(fx, "base64_blob.js")),
      "04_app.min.js": readFileSync(join(fx, "app.min.js")),
      "05_app.min.js.map": readFileSync(join(fx, "app.min.js.map")),
    });
    const mpath = join(root, "targets", host, "captures", "manifest.json");
    const m = readJson(mpath);
    const mapAsset = m.assets.find((a) => a.raw_ref.endsWith("05_app.min.js.map"));
    mapAsset.asset_kind = "sourcemap";
    writeJson(mpath, m);

    const db = run(PY, ["scripts/deobfuscate.py", host]);
    assert.equal(db.status, 0, db.stderr || db.stdout);
    const doc = readJson(join(root, "targets", host, "findings.json"));
    const eps = doc.findings.filter((f) => f.asset_kind === "endpoint"
      && String(f.evidence_path).includes("captures/decoded"));
    const hidden = ["/api/hidden/config", "/api/admin/storage", "https://hidden.example.com/api/secret",
      "https://api.hidden.com/v1/users", "https://admin.internal.example/storage"];
    for (const h of hidden) {
      assert.ok(eps.some((f) => (f.endpoint || f.evidence_quote).includes(h)),
        `디코드본에서 숨은 엔드포인트 발견 필요: ${h}`);
    }
    const m2 = readJson(mpath);
    assert.ok(m2.assets.some((a) => a.derived_from && a.decoder), "디코더/원본 추적 필요");
    assert.equal(gate(host).decision, "GO", gate(host).out);
  } finally {
    rmSync(join(root, "targets", host), { recursive: true, force: true });
  }
});

test("merge_fallback: 유효 인용 병합·unknown 보존·fabricated 거부", () => {
  const host = "it-" + Date.now();
  try {
    makeTarget(host, {
      "01_app.js": "window.ACME = { name: 'acme-ui', version: '4.7.1' };\n",
      "02_style.css": "body{}\n",
    });
    assert.equal(run(PY, ["scripts/fingerprint.py", host]).status, 0);
    const fpath = join(root, "targets", host, "findings.json");
    const before = readJson(fpath);
    const unmatchedId = before.unmatched[0].asset_id;
    assert.ok(unmatchedId, "unmatched 존재 필요");
    const jpath = join(root, "targets", host, "judgments-tmp.json");
    writeJson(jpath, { judgments: [
      { asset_id: unmatchedId, product: "acme-ui", version: "4.7.1", provenance: "inferred",
        evidence_quote: "name: 'acme-ui', version: '4.7.1'", reasoning: "번들 내부 패키지 메타데이터" },
      { asset_id: "does-not-exist", provenance: "unknown", product: "unidentified", version: "unknown" },
    ] });
    const mg = run(PY, ["scripts/merge_fallback.py", host, jpath]);
    assert.equal(mg.status, 1);
    const after = readJson(fpath);
    assert.ok(after.findings.some((f) => f.product === "acme-ui" && f.provenance === "inferred"),
      "유효 인용은 inferred 로 병합/업그레이드");
    assert.ok(!after.unmatched.some((u) => u.asset_id === unmatchedId), "병합된 자산은 unmatched 에서 제거");
    assert.equal(gate(host).decision, "GO", gate(host).out);
  } finally {
    rmSync(join(root, "targets", host), { recursive: true, force: true });
  }
});

test("T22: WAF/CDN 패시브 탐지 (헤더/쿠키 confirmed) + 게이트 GO", () => {
  const host = "it-" + Date.now();
  try {
    makeTarget(host, {
      "__headers__.txt": "cf-ray: 8a1b2c3d4e5f-ICN\nServer: cloudflare\nX-Sucuri-ID: 12345\n",
      "__cookies__.txt": "__cf_bm=abc; Path=/\nwfvt_123=xyz; Path=/\n",
    });
    const fp = run(PY, ["scripts/fingerprint.py", host]);
    assert.equal(fp.status, 0, fp.stderr || fp.stdout);
    const doc = readJson(join(root, "targets", host, "findings.json"));
    assert.ok(doc.findings.some((f) => f.product === "WAF" && f.provenance === "confirmed" && /cf-ray/.test(f.evidence_quote)),
      "Cloudflare WAF confirmed 필요");
    assert.ok(doc.findings.some((f) => f.product === "WAF" && f.provenance === "confirmed" && /wfvt_/.test(f.evidence_quote)),
      "Wordfence WAF confirmed 필요");
    assert.ok(doc.findings.some((f) => f.product === "CDN" && f.provenance === "confirmed"),
      "Cloudflare CDN confirmed 필요");
    assert.equal(gate(host).decision, "GO", gate(host).out);
  } finally {
    rmSync(join(root, "targets", host), { recursive: true, force: true });
  }
});

test("T22: waf_recon GO 게이트(STOP) + 능동 프로브로 차단→inferred", async () => {
  const host = "it-" + Date.now();
  let server = null;
  try {
    makeTarget(host, { "01_app.js": "/*! jQuery JavaScript Library v3.6.0 */\n" });
    assert.equal(run(PY, ["scripts/fingerprint.py", host]).status, 0, "findings.json 생성");
    const noGo = run(PY, ["scripts/waf_recon.py", "--url", "http://127.0.0.1:8915/", "--ip", "127.0.0.1",
      "--target", host, "--recon-id", "R-WAF", "--payloads"]);
    assert.equal(noGo.status, 3, "GO 없이는 STOP(exit 3)");
    const { spawn } = await import("node:child_process");
    server = spawn(PY, [join(root, "tests/fixtures/waf_server.py")], { stdio: "ignore" });
    await new Promise((r) => setTimeout(r, 1500));
    const run2 = run(PY, ["scripts/waf_recon.py", "--url", "http://127.0.0.1:8915/", "--ip", "127.0.0.1",
      "--target", host, "--recon-id", "R-WAF2", "--approved", "--payloads"]);
    assert.equal(run2.status, 0, run2.stderr || run2.stdout);
    const doc = readJson(join(root, "targets", host, "findings.json"));
    assert.ok(doc.findings.some((f) => f.product === "waf" && f.provenance === "inferred"),
      "차단 행위 관찰 → WAF inferred 필요");
    assert.equal(gate(host).decision, "GO", gate(host).out);
  } finally {
    if (server) server.kill();
    rmSync(join(root, "targets", host), { recursive: true, force: true });
  }
});
