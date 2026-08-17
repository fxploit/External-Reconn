#!/usr/bin/env python3
"""스크립트 자가개선(self-repair) 메커니즘 (T20).

harness/policies/self-repair.md 정책을 코드로 강제한다:
 - scripts/variants/ 디렉터리 규약(사본 생성, 원본 불변)
 - 신뢰 앵커(게이트·검증기·계약) 자가수정 차단 가드레일
 - targets/<host>/self-repair-log.md(+.json) 표준 로그
 - 채택 게이트: npm test + 타깃 게이트 통과 시에만 채택(실패 시 폐기)

사용 (CLI):
    python scripts/lib/self_repair.py new-variant <source> --target <host>
    python scripts/lib/self_repair.py log <host> <entry.json>
    python scripts/lib/self_repair.py verify <host> [--expected GO]

모듈로도 사용 가능(from scripts.lib.self_repair import make_variant, ...)
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VARIANTS_DIR = os.path.join(ROOT, "scripts", "variants")

# 정책 §1 — 절대 자가수정 금지 (신뢰 앵커)
TRUST_ANCHORS = [
    os.path.join(ROOT, "scripts", "check-recon.mjs"),
    os.path.join(ROOT, "scripts", "lib", "checks.mjs"),
    os.path.join(ROOT, "AGENTS.md"),
    os.path.join(ROOT, "harness", "policies", "invariants.md"),
]
# 정책 §2 — 자가개선 허용 대상 (데이터 수집 계층)
ALLOWED_BASENAMES = {
    "collect_web.py", "collect_spa.py", "normalize_js.py",
    "active_recon.py", "discover_vhost.py", "discover_dns.py",
    "extract_assets.py", "aws_recon.py",
}


def _utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _variant_name(source_path, target) -> str:
    base = os.path.basename(source_path)
    ts = _now().replace(":", "").replace("-", "").replace("Z", "")  # YYYYMMDDTHHMMSS
    return f"{base}.{re.sub(r'[^A-Za-z0-9._-]', '_', target)}.{ts}"


def guardrail_error(source_path) -> str:
    """신뢰 앵커/허용 대상 외 경로에 대한 가드레일 사유. 없으면 None."""
    resolved = os.path.abspath(source_path)
    for anchor in TRUST_ANCHORS:
        if resolved == os.path.abspath(anchor):
            return f"신뢰 앵커 자가수정 금지: {os.path.relpath(anchor, ROOT)} — STOP, 사람에게 보고"
    if os.path.basename(source_path) not in ALLOWED_BASENAMES:
        return (f"자가개선 허용 대상 아님: {source_path} "
                f"(허용: {sorted(ALLOWED_BASENAMES)})")
    if not os.path.exists(resolved):
        return f"원본 없음: {source_path}"
    return None


def make_variant(source_path, target):
    """사본을 scripts/variants/ 에 만든다(원본 불변). 가드레일 위반이면 예외."""
    reason = guardrail_error(source_path)
    if reason:
        raise PermissionError(reason)
    os.makedirs(VARIANTS_DIR, exist_ok=True)
    name = _variant_name(source_path, target)
    dest = os.path.join(VARIANTS_DIR, name)
    shutil.copy2(source_path, dest)
    return dest


def log_entry(target, entry):
    """self-repair-log.md(.json) 에 항목을 append(실패 시도도 보존)."""
    ldir = os.path.join(ROOT, "targets", target)
    os.makedirs(ldir, exist_ok=True)
    entry.setdefault("timestamp", _now())
    # 기계가독 로그
    jpath = os.path.join(ldir, "self-repair-log.json")
    records = []
    if os.path.exists(jpath):
        try:
            with open(jpath, encoding="utf-8") as f:
                records = json.load(f)
        except json.JSONDecodeError:
            records = []
    records.append(entry)
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)

    # 사람 가독 로그
    mpath = os.path.join(ldir, "self-repair-log.md")
    lines = [
        f"## {entry.get('timestamp')} {entry.get('source', '')}",
        f"- 사본: {entry.get('variant', '')}",
        f"- 증상: {entry.get('symptom', '')} (Observation ref: {entry.get('observation_ref', '')})",
        f"- 원인 가설: {entry.get('hypothesis', '')}",
        f"- 변경 요약: {entry.get('change_summary', '')}",
        f"- 검증: npm test = {entry.get('npm_test', '?')}, gate({target}) = {entry.get('gate', '?')}",
        f"- 판정: {entry.get('verdict', '?')}",
        "",
    ]
    with open(mpath, "a", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))
    return mpath


def verify(target, expected="GO"):
    """채택 게이트: npm test + npm run check -- <target>.
    반환: (test_ok, gate_decision, gate_ok) — expected 와 gate_decision 일치해야 gate_ok.
    """
    test = subprocess.run(["npm", "test"], cwd=ROOT, capture_output=True, text=True, timeout=600)
    test_ok = test.returncode == 0
    gate_run = subprocess.run(["node", "scripts/check-recon.mjs", target], cwd=ROOT,
                              capture_output=True, text=True, timeout=120)
    m = re.search(r"DECISION=(\w+)", gate_run.stdout)
    decision = m.group(1) if m else "?"
    gate_ok = decision == expected
    return test_ok, decision, gate_ok


def _read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    _utf8_stdio()
    ap = argparse.ArgumentParser(description="Self-repair mechanism (variants/guardrail/log/verify)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("new-variant", help="허용 대상의 사본 생성(신뢰 앵커는 차단)")
    p1.add_argument("source")
    p1.add_argument("--target", default="local")

    p2 = sub.add_parser("log", help="자가개선 로그 append (entry JSON)")
    p2.add_argument("target")
    p2.add_argument("entry", help="entry 필드 JSON 파일")

    p3 = sub.add_parser("verify", help="채택 게이트 검증(npm test + gate)")
    p3.add_argument("target")
    p3.add_argument("--expected", default="GO")

    args = ap.parse_args()
    if args.cmd == "new-variant":
        try:
            dest = make_variant(args.source, args.target)
        except PermissionError as e:
            print(f"[STOP] {e}", file=sys.stderr)
            return 3
        print(dest)
        return 0
    if args.cmd == "log":
        entry = _read_json(args.entry)
        p = log_entry(args.target, entry)
        print(f"[*] 로그 append: {os.path.relpath(p, ROOT)}")
        return 0
    if args.cmd == "verify":
        test_ok, decision, gate_ok = verify(args.target, args.expected)
        print(f"[*] npm test = {'pass' if test_ok else 'fail'} / gate({args.target}) = {decision}")
        if test_ok and gate_ok:
            print("[*] 채택 조건 충족")
            return 0
        print("[!] 채택 조건 불충족 — 변형본 폐기(원본 유지)", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
