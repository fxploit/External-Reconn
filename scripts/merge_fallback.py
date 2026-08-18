#!/usr/bin/env python3
"""AI fallback 판정 병합 — findings.json 의 unmatched[] 에 서브에이전트 판정을 병합.

서브에이전트가 harness/prompts/fallback-inference.md 계약대로 낸 판정 JSON 을 받아:
 - provenance ∈ {inferred, guess} → finding 으로 승격, unmatched 에서 제거
 - provenance == unknown → unmatched 에 그대로 유지(삭제 금지, invariants)
 - evidence_quote 는 병합 '전에' evidence_path 파일 바이트에 존재하는지 확인한다
   (fabricated 인용을 게이트가 아닌 이 단계에서도 거부). 없으면 해당 판정은 REVISE 로 보존.
 - 'confirmed' 판정이 오면 거부한다(계약 위반 — AI는 confirmed 자가 승격 금지).

Usage:
    python scripts/merge_fallback.py <host> <judgments.json>
"""
import argparse
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALLOWED = {"inferred", "guess", "unknown"}
from lib.engagement import append_event, stamp_findings  # noqa: E402


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _utf8_stdio():
    """Windows 콘솔(CP949)에서 한글/특수문자 출력이 깨지거나 크래시하지 않게 표준 스트림을 UTF-8로."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main() -> int:
    _utf8_stdio()
    ap = argparse.ArgumentParser(description="Merge AI fallback judgments into findings.json")
    ap.add_argument("target", help="host label (targets/<host>/)")
    ap.add_argument("judgments", help="서브에이전트 판정 JSON (배열 또는 {judgments: [...]})")
    args = ap.parse_args()

    fpath = os.path.join(ROOT, "targets", args.target, "findings.json")
    if not os.path.exists(fpath):
        print(f"[!] findings.json not found: {fpath} — run fingerprint.py first", file=sys.stderr)
        return 2
    with open(fpath, encoding="utf-8") as f:
        doc = json.load(f)

    with open(args.judgments, encoding="utf-8") as f:
        raw = json.load(f)
    judgments = raw.get("judgments") if isinstance(raw, dict) else raw
    if not isinstance(judgments, list):
        print("[!] judgments must be a JSON array (or {\"judgments\": [...]})", file=sys.stderr)
        return 2

    unmatched = doc.get("unmatched", [])
    findings = doc.get("findings", [])
    by_id = {u.get("asset_id"): u for u in unmatched}
    kept_unknown = []  # 판정이 unknown 이라 unmatched 에 유지되는 항목
    rejected = []      # 계약 위반/근거 부재로 병합 거부(삭제하지 않고 로그+보존)
    merged_ids = set() # 이미 병합된 asset_id — 중복 판정 가드
    fid_max = max([int(f["finding_id"].split("-")[-1]) for f in findings] or [0])

    for j in judgments:
        aid = j.get("asset_id")
        src = by_id.get(aid)
        prov = j.get("provenance")
        if src is None:
            rejected.append({"asset_id": aid, "reason": "unmatched 에 없는 asset_id"})
            continue
        if aid in merged_ids:
            rejected.append({"asset_id": aid, "reason": "이미 병합된 asset_id 중복 판정"})
            continue
        if prov not in ALLOWED:
            rejected.append({"asset_id": aid, "reason": f"provenance '{prov}' (allowed: {sorted(ALLOWED)})"})
            continue

        if prov == "unknown":
            # 판단 불가는 unmatched 에 유지(삭제 금지). 사람/다음 하네스가 이어받는다.
            kept_unknown.append(aid)
            continue

        # inferred/guess — 근거 바인딩 검증 (게이트와 동일: quote의 UTF-8 바이트를 파일에서 검색)
        quote = j.get("evidence_quote", "")
        ev_path = src.get("evidence_path") or j.get("evidence_path")
        if not quote:
            rejected.append({"asset_id": aid, "reason": "evidence_quote 없음(인용 없는 추측 금지)"})
            continue
        if not ev_path or not os.path.exists(os.path.join(ROOT, ev_path)):
            rejected.append({"asset_id": aid, "reason": f"evidence_path 없음: {ev_path}"})
            continue
        data = open(os.path.join(ROOT, ev_path), "rb").read()
        if quote.encode("utf-8") not in data:
            rejected.append({
                "asset_id": aid,
                "reason": "evidence_quote not found in asset — fabricated",
                "evidence_path": ev_path,
            })
            continue

        fid_max += 1
        # 기존 unknown 발견(evidence_path 로 상관)이 있으면 업그레이드, 없으면 신규 추가
        target = next((f for f in findings if f.get("evidence_path") == ev_path), None)
        if target is not None:
            target.update({
                "product": j.get("product", "unidentified"),
                "version": j.get("version", "unknown"),
                "version_bound": j.get("version_bound", "UNSET"),
                "provenance": prov,
                "evidence_path": ev_path,
                "evidence_quote": quote,
                "asset_sha256": sha256_hex(data),
                "reasoning": "ai-fallback: " + j.get("reasoning", ""),
                "verified_by": ["fallback-inference:" + (j.get("reasoning") or "").strip()[:40]],
                "report_eligible": False,
            })
            print(f"[+] upgraded {aid} -> {target['finding_id']} ({prov}) quote={quote[:60]!r}")
        else:
            findings.append({
                "finding_id": f"FND-{fid_max:03d}",
                "asset_kind": src.get("asset_kind", "other"),
                "product": j.get("product", "unidentified"),
                "version": j.get("version", "unknown"),
                "version_bound": j.get("version_bound", "UNSET"),
                "provenance": prov,
                "evidence_path": ev_path,
                "evidence_quote": quote,
                "asset_sha256": sha256_hex(data),
                "reasoning": "ai-fallback: " + j.get("reasoning", ""),
                "verified_by": ["fallback-inference:" + (j.get("reasoning") or "").strip()[:40]],
                "report_eligible": False,
            })
            print(f"[+] merged {aid} -> FND-{fid_max:03d} ({prov}) quote={quote[:60]!r}")
        merged_ids.add(aid)

    # unmatched 재구성: unknown 은 유지, 병합된 항목은 제거, 거부 항목은 유지(단 병합된 항목 제외)
    kept_ids = (set(kept_unknown) | set(r.get("asset_id") for r in rejected)) - merged_ids
    stamp_findings(findings, "merge_fallback.py")
    doc["unmatched"] = [u for u in unmatched if u.get("asset_id") in kept_ids]
    doc["findings"] = findings

    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    append_event(args.target, {"event": "merge_fallback", "produced_by": "merge_fallback.py",
                               "findings_ref": f"targets/{args.target}/findings.json"})

    print(f"[*] merged={len(findings)} total findings, unmatched={len(doc['unmatched'])}")
    if kept_unknown:
        print(f"[i] unknown 유지(보존): {sorted(kept_unknown)}")
    if rejected:
        print(f"[!] 병합 거부(rejected) {len(rejected)} — REVISE 대상:")
        for r in rejected:
            print("    - " + json.dumps(r, ensure_ascii=False))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
