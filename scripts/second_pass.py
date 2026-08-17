#!/usr/bin/env python3
"""2차 재검증 러너 — 고가치 발견을 맥락 제거 상태로 재판정하고 verified_by 를 갱신한다.

harness/prompts/second-pass-verify.md 계약에 따라:
 - --prepare: 재판정 대상(confirmed 또는 --finding-id 지정)의 '증거만' 뽑아
   targets/<host>/captures/observation/second-pass-input.json 을 만든다(맥락 제거).
 - --apply: 서브에이전트 판정(verdicts.json)을 적용한다.
   support  → verified_by += second-pass:support, provenance 유지
   contradict → verified_by += second-pass:contradict, confirmed 는 inferred 로 강등
   unknown  → verified_by += second-pass:unknown, 등급 불변(보수적)

게이트(checks.mjs)는 verified_by 에 second-pass 가 있으면 confirmed 근거로 인정한다.
따라서 이 경로를 채우면 결정론 도구 매칭과 독립된 재검증으로 confirmed 가 확정된다.

Usage:
    python scripts/second_pass.py <host> --prepare [--finding-id FND-003]...
    python scripts/second_pass.py <host> --apply verdicts.json
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXCERPT_BYTES = 4000


def _utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def load_doc(host):
    fpath = os.path.join(ROOT, "targets", host, "findings.json")
    if not os.path.exists(fpath):
        print(f"[!] findings.json not found: {fpath} — run fingerprint.py first", file=sys.stderr)
        return None, None
    with open(fpath, encoding="utf-8") as f:
        doc = json.load(f)
    return fpath, doc


def excerpt_of(evidence_path, quote):
    p = os.path.join(ROOT, evidence_path)
    if not os.path.exists(p):
        return None
    data = open(p, "rb").read()
    needle = quote.encode("utf-8")
    idx = data.find(needle)
    start = max(0, idx - EXCERPT_BYTES // 2) if idx >= 0 else 0
    raw = data[start:start + EXCERPT_BYTES]
    for enc in ("utf-8-sig", "utf-8", "cp949"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1")


def prepare(host, finding_ids):
    fpath, doc = load_doc(host)
    if doc is None:
        return 2
    findings = doc.get("findings", [])
    if finding_ids:
        sel = [f for f in findings if f["finding_id"] in finding_ids]
    else:
        sel = [f for f in findings if f["provenance"] == "confirmed"]
    if not sel:
        print("[!] 재검증 대상 발견이 없습니다(--finding-id 지정 또는 confirmed 항목 필요)", file=sys.stderr)
        return 2

    out = []
    for f in sel:
        ep = f.get("evidence_path")
        q = f.get("evidence_quote")
        if not ep or not q or q == "UNSET":
            continue
        out.append({
            "finding_id": f["finding_id"],
            "asset_kind": f.get("asset_kind"),
            "evidence_quote": q,
            "evidence_excerpt": excerpt_of(ep, q),
        })
    opath = os.path.join(ROOT, "targets", host, "captures", "observation", "second-pass-input.json")
    with open(opath, "w", encoding="utf-8") as fo:
        json.dump({"second_pass_input": out}, fo, indent=2, ensure_ascii=False)
    print(f"[*] second-pass 입력 {len(out)}건: {os.path.relpath(opath, ROOT)}")
    print("    서브에이전트가 판정 후: python scripts/second_pass.py " + host + " --apply verdicts.json")
    return 0


def apply_verdicts(host, verdicts_path):
    fpath, doc = load_doc(host)
    if doc is None:
        return 2
    with open(verdicts_path, encoding="utf-8") as f:
        raw = json.load(f)
    verdicts = raw.get("verdicts") if isinstance(raw, dict) else raw
    if not isinstance(verdicts, list):
        print("[!] verdicts must be a JSON array (or {\"verdicts\": [...]})", file=sys.stderr)
        return 2

    by_id = {f["finding_id"]: f for f in doc.get("findings", [])}
    n_support = n_contradict = n_unknown = n_miss = 0
    for v in verdicts:
        fid = v.get("finding_id")
        verdict = v.get("verdict")
        f = by_id.get(fid)
        if f is None:
            print(f"[!] 없는 finding_id: {fid} (무시)", file=sys.stderr)
            n_miss += 1
            continue
        vb = f.setdefault("verified_by", [])
        if verdict == "support":
            vb.append("second-pass:support")
            n_support += 1
            print(f"[+] {fid} support — provenance 유지({f['provenance']})")
        elif verdict == "contradict":
            vb.append("second-pass:contradict")
            if f["provenance"] == "confirmed":
                print(f"[!] {fid} contradict — 1차 판정과 상충 → confirmed 에서 inferred 로 강등")
                f["provenance"] = "inferred"
            else:
                print(f"[!] {fid} contradict — 등급 유지({f['provenance']})")
            n_contradict += 1
        elif verdict == "unknown":
            vb.append("second-pass:unknown")
            n_unknown += 1
            print(f"[?] {fid} unknown — 등급 불변(보수적)")
        else:
            print(f"[!] {fid} 잘못된 verdict: {verdict} (support/contradict/unknown)", file=sys.stderr)
            n_miss += 1

    with open(fpath, "w", encoding="utf-8") as fo:
        json.dump(doc, fo, indent=2, ensure_ascii=False)
    print(f"[*] 적용 완료: support={n_support} contradict={n_contradict} unknown={n_unknown} miss={n_miss}")
    print("[*] 게이트 확인: npm run check -- " + host)
    return 0


def main() -> int:
    _utf8_stdio()
    ap = argparse.ArgumentParser(description="Second-pass verification runner")
    ap.add_argument("target", help="host label (targets/<host>/)")
    ap.add_argument("--prepare", action="store_true", help="재판정 입력(증거만) 생성")
    ap.add_argument("--apply", metavar="verdicts.json", help="판정 적용")
    ap.add_argument("--finding-id", action="append", default=[], help="대상 finding_id (반복 가능)")
    args = ap.parse_args()

    if args.prepare and args.apply:
        print("[!] --prepare 와 --apply 는 동시에 쓸 수 없습니다", file=sys.stderr)
        return 2
    if args.prepare:
        return prepare(args.target, args.finding_id)
    if args.apply:
        return apply_verdicts(args.target, args.apply)
    print("[!] --prepare 또는 --apply 중 하나를 지정하세요", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
