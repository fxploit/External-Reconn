import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { createHash } from "node:crypto";

const PROVENANCE = new Set(["confirmed", "inferred", "guess", "unknown"]);

function sha256Hex(content) {
  return createHash("sha256").update(content).digest("hex");
}
function isHashLike(v) {
  return typeof v === "string" && /^[a-f0-9]{64}$/i.test(v);
}

function discoverTarget(root, hint) {
  const dir = resolve(root, "targets");
  if (!existsSync(dir)) return null;
  const all = readdirSync(dir).filter((e) => {
    try {
      return statSync(resolve(dir, e)).isDirectory() && e !== ".gitkeep";
    } catch {
      return false;
    }
  });
  if (!all.length) return null;
  if (hint) {
    return all.includes(hint) ? hint : "__NOT_FOUND__:" + hint;
  }
  if (all.length > 1) return "__AMBIGUOUS__:" + all.sort().join(", ");
  return all[0];
}

// --- scope (CIDR) -----------------------------------------------------------
function ipToInt(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}
function inCidr(ip, cidr) {
  const [net, bitsRaw] = cidr.split("/");
  const bits = bitsRaw === undefined ? 32 : parseInt(bitsRaw, 10);
  const ipInt = ipToInt(ip);
  const netInt = ipToInt(net);
  if (ipInt === null || netInt === null || bits < 0 || bits > 32) return false;
  if (bits === 0) return true;
  const mask = bits === 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}
function isIpv4(s) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
}

function read(root, rel, issues) {
  const file = resolve(root, rel);
  if (!existsSync(file)) {
    issues.push(rel + ": missing");
    return "";
  }
  return readFileSync(file, "utf8");
}
function readJson(root, rel, issues) {
  const content = read(root, rel, issues);
  if (!content) return null;
  try {
    return JSON.parse(content);
  } catch {
    issues.push(rel + ": invalid JSON");
    return null;
  }
}

function checkScope(root, targetLabel, issues) {
  const scope = read(root, "scope.md", issues);
  // 주석(<!-- ... -->)을 먼저 제거 — 활성 라인이 지워졌을 때 예시 대역이 조용히 활성화되는 것 방지(T19#5)
  const noComments = scope.replace(/<!--[\s\S]*?-->/g, "");
  const line = noComments.match(/허용 대역:\s*(.+)/)?.[1]?.trim();
  if (!line || line === "UNSET") {
    issues.push("scope.md: 허용 대역 미설정(UNSET) — CTF가 지정한 허용 대역으로 갱신해야 정찰 GO");
    return;
  }
  const ranges = line.split(",").map((s) => s.trim()).filter(Boolean);
  // 타깃 라벨이 IP면 대역 포함 여부를 검사한다(라벨이 IP가 아니면 런타임에서 확인).
  if (isIpv4(targetLabel)) {
    const ok = ranges.some((r) => inCidr(targetLabel, r));
    if (!ok) {
      issues.push(
        "STOP scope.md: target " + targetLabel + " 은 허용 대역(" + ranges.join(", ") + ") 밖 — 정찰 금지"
      );
    }
  }
}

function checkFindings(root, target, issues) {
  const base = "targets/" + target;
  const manifest = readJson(root, base + "/captures/manifest.json", issues);
  if (manifest && manifest.target && manifest.target !== target) {
    issues.push(base + "/captures/manifest.json: target mismatch (" + manifest.target + ")");
  }

  const findingsDoc = readJson(root, base + "/findings.json", issues);
  if (!findingsDoc) return;
  const findings = Array.isArray(findingsDoc.findings) ? findingsDoc.findings : [];
  if (!findings.length) {
    issues.push(base + "/findings.json: no findings (unknown도 명시적 항목이어야 함)");
  }

  for (const f of findings) {
    const label = base + "/findings.json#" + (f.finding_id || "?");

    if (!PROVENANCE.has(f.provenance)) {
      issues.push(label + ": invalid provenance '" + f.provenance + "'");
      continue;
    }

    // 근거 자산 바인딩 — evidence_path가 있으면 실재해야 하고 quote/hash가 재검증돼야 한다.
    let fileContent = null;
    if (f.evidence_path && f.evidence_path !== "UNSET") {
      const p = resolve(root, f.evidence_path);
      if (!existsSync(p)) {
        issues.push(label + ": evidence_path points to a missing file (" + f.evidence_path + ")");
      } else {
        fileContent = readFileSync(p);
        // asset_sha256 재계산 검증 (fabricated hash 차단)
        if (isHashLike(f.asset_sha256)) {
          const actual = sha256Hex(fileContent);
          if (actual !== f.asset_sha256) {
            issues.push(
              label + ": asset_sha256 does not match sha256(evidence file) — fabricated rather than computed"
            );
          }
        }
        // evidence_quote 가 실제 파일 부분 문자열인지 검증 (fabricated quote 차단).
        // 파일을 UTF-8로 디코딩하지 않고 quote의 UTF-8 '바이트'를 파일 바이트에서 직접 찾는다.
        // 원본이 CP949/EUC-KR/UTF-8-BOM 이어도 인코딩과 무관하게 재검증이 일치한다
        // (fingerprint.py 의 bind_evidence 가 동일하게 UTF-8 바이트 기준으로 바인딩).
        if (f.evidence_quote && f.evidence_quote !== "UNSET") {
          if (!fileContent.includes(Buffer.from(f.evidence_quote, "utf8"))) {
            issues.push(
              label +
                ": evidence_quote not found in evidence_path file — quote may be fabricated rather than copied from the asset"
            );
          }
        }
      }
    }

    // confirmed 승격 규율
    if (f.provenance === "confirmed") {
      if (!f.evidence_path || f.evidence_path === "UNSET") {
        issues.push(label + ": confirmed requires evidence_path");
      }
      if (!f.evidence_quote || f.evidence_quote === "UNSET") {
        issues.push(label + ": confirmed requires evidence_quote (원본에 실재하는 근거)");
      }
      if (!isHashLike(f.asset_sha256)) {
        issues.push(label + ": confirmed requires a real asset_sha256");
      }
      // AI는 confirmed로 자가 승격 불가 — 결정론적 도구 또는 재검증 근거가 있어야 한다.
      const vb = Array.isArray(f.verified_by) ? f.verified_by : [];
      const hasDeterministic = vb.some(
        (v) =>
          /^(fingerprint\.py|active_recon\.py|discover_vhost\.py|extract_assets\.py|discover_dns\.py|aws_recon\.py|waf_recon\.py):/.test(v) ||
          /second-pass/i.test(v)
      );
      if (!hasDeterministic) {
        issues.push(
          label +
            ": confirmed 는 결정론적 도구 매칭(fingerprint.py:*/active_recon.py:*/extract_assets.py:*) 또는 second-pass 재검증이 verified_by 에 있어야 함 — AI 자가 승격 금지"
        );
      }
    }
  }
}

export function checkTarget(root, hint) {
  const issues = [];
  const target = discoverTarget(root, hint);
  if (!target) {
    issues.push("targets/: no target workspace found — scripts/new-target.mjs <host> 로 생성하세요");
    return issues;
  }
  if (target.startsWith("__NOT_FOUND__:")) {
    issues.push("targets/: " + target.slice(14) + " workspace not found");
    return issues;
  }
  if (target.startsWith("__AMBIGUOUS__:")) {
    issues.push(
      "targets/: 대상이 여러 개입니다(" + target.slice(14) + "). npm run check -- <host> 로 명시하세요."
    );
    return issues;
  }
  checkScope(root, target, issues);
  checkFindings(root, target, issues);
  return issues;
}

export function classifyDecision(issues) {
  if (!issues.length) return "GO";
  if (issues.some((i) => i.startsWith("STOP "))) return "STOP";
  return "REVISE";
}
