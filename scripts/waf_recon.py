#!/usr/bin/env python3
"""방어 태세(defense posture) 탐지 — WAF/CDN/IPS/레이트리밋 (T22).

- 패시브(저위험): WAF/CDN 헤더·쿠키·차단페이지 마커는 harness/signatures/waf.json·cdn.json 데이터를
  fingerprint.py 가 탐지한다(이 스크립트 아님).
- 능동(이 스크립트, ⚠️ GO 필수):
  - --wafw00f: 성숙 도구(wafw00f) 실행, JSON 출력을 finding 으로 파싱(도구 출력 실재 → confirmed).
  - --payloads: 무해한 엔드포인트에 소량 벤치 페이로드 → 차단 반응(403/406/429/501) 관찰 → WAF/IPS inferred.
    **트립(차단 관찰) 시 즉시 중단·사람 보고**(방어를 건드릴 수 있음).
  - --rate N: baseline 대비 N 요청 후 429/드롭 관찰 → ratelimit inferred.
- 결과 클래스 분리(invariants): transport 실패(RST/timeout)와 정상 403/404, WAF 차단페이지를 구분.
- 정직한 경계: 순수 패시브 IDS 는 대개 탐지 불가 → unknown 보존(지어내지 않는다).

Usage:
    python scripts/waf_recon.py --url https://lab.example/ --ip 10.0.0.1 --target lab.example \
        --recon-id RECON-05 --approved --wafw00f --payloads --rate 15
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect_web import fetch, now_iso  # noqa: E402

BLOCK_STATUS = {403, 406, 418, 429, 501, 503}
BENIGN_PAYLOADS = [
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "../../../../etc/passwd",
    "' OR '1'='1",
]


def _utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def scope_allows(ip):
    spath = os.path.join(ROOT, "scope.md")
    if not os.path.exists(spath):
        return False
    with open(spath, encoding="utf-8") as f:
        content = f.read()
    content = re.sub(r"<!--[\s\S]*?-->", "", content)
    m = re.search(r"허용 대역:\s*(.+)", content)
    if not m or "UNSET" in m.group(1):
        return False
    ranges = [r.strip() for r in m.group(1).split(",") if r.strip()]

    def ip_int(a):
        p = a.split(".")
        if len(p) != 4:
            return None
        try:
            n = [int(x) for x in p]
        except ValueError:
            return None
        if any(x < 0 or x > 255 for x in n):
            return None
        return (n[0] << 24) + (n[1] << 16) + (n[2] << 8) + n[3]

    def in_cidr(a, cidr):
        net, _, bits = cidr.partition("/")
        b = int(bits) if bits else 32
        ai, ni = ip_int(a), ip_int(net)
        if ai is None or ni is None or b < 0 or b > 32:
            return False
        if b == 0:
            return True
        mask = (0xFFFFFFFF << (32 - b)) & 0xFFFFFFFF
        return (ai & mask) == (ni & mask)

    return any(in_cidr(ip, r) for r in ranges)


def append_finding(target, finding):
    fpath = os.path.join(ROOT, "targets", target, "findings.json")
    if not os.path.exists(fpath):
        return
    with open(fpath, encoding="utf-8") as f:
        doc = json.load(f)
    findings = doc.setdefault("findings", [])
    nums = [int(x["finding_id"].split("-")[-1]) for x in findings
            if x["finding_id"].split("-")[-1].isdigit()]
    fid = max(nums or [0]) + 1
    finding["finding_id"] = f"FND-{fid:03d}"
    finding["report_eligible"] = False
    findings.append(finding)
    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    print(f"[+] finding FND-{fid:03d}: {finding['product']} {finding['version']} ({finding['provenance']})")


def run_wafw00f(url, target, recon_id):
    binary = shutil.which("wafw00f")
    if not binary:
        print("[!] wafw00f 없음(컨테이너 실행 권장) — 생략", file=sys.stderr)
        return 0
    odir = os.path.join(ROOT, "targets", target, "captures", "observation")
    os.makedirs(odir, exist_ok=True)
    out_json = os.path.join(odir, f"wafw00f-{recon_id}.json")
    try:
        proc = subprocess.run([binary, url, "-r", "-o", out_json, "-f", "json", "-a"],
                              capture_output=True, text=True, timeout=300)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"[!] wafw00f 실행 실패: {e}", file=sys.stderr)
        return 0
    txt = os.path.join(odir, f"wafw00f-{recon_id}.txt")
    with open(txt, "w", encoding="utf-8", newline="\n") as f:
        f.write(proc.stdout or "")
        if proc.stderr:
            f.write("\n--- stderr ---\n" + proc.stderr)
    print(f"[*] wafw00f stdout -> {os.path.relpath(txt, ROOT)} (exit={proc.returncode})")

    added = 0
    if os.path.exists(out_json):
        try:
            with open(out_json, encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = []
        raw = open(out_json, "rb").read()
        sha = hashlib.sha256(raw).hexdigest()
        for item in (data if isinstance(data, list) else [data]):
            if not isinstance(item, dict):
                continue
            waf = item.get("firewall") or item.get("wafname") or item.get("waf")
            detected = item.get("detected")
            if not waf or waf == "None" or detected is False:
                continue
            append_finding(target, {
                "asset_kind": "defense",
                "product": "waf",
                "version": str(waf),
                "version_bound": "UNSET",
                "provenance": "confirmed",
                "evidence_path": os.path.relpath(out_json, ROOT).replace("\\", "/"),
                "evidence_quote": f'"firewall": "{waf}"',
                "asset_sha256": sha,
                "reasoning": f"wafw00f({recon_id}): {url} 뒤 WAF '{waf}' 탐지 — 도구 JSON 출력 실재(confirmed)",
                "verified_by": [f"waf_recon.py:wafw00f:{recon_id}"],
            })
            added += 1
    return added


def _bind_finding(obs, odir, target, recon_id, name, finding):
    """observation 파일을 먼저 쓰고 sha/인용을 바인딩(evidence 는 실재 파일 기준)."""
    opath = os.path.join(odir, f"{name}-{recon_id}.json")
    with open(opath, "w", encoding="utf-8") as f:
        json.dump(obs, f, indent=2, ensure_ascii=False)
    raw = open(opath, "rb").read()
    finding["evidence_path"] = os.path.relpath(opath, ROOT).replace("\\", "/")
    finding["asset_sha256"] = hashlib.sha256(raw).hexdigest()
    append_finding(target, finding)


def probe_payloads(url, target, recon_id):
    """소량 벤치 페이로드 → 차단 반응 관찰. 트립 시 즉시 중단."""
    odir = os.path.join(ROOT, "targets", target, "captures", "observation")
    os.makedirs(odir, exist_ok=True)
    obs = {"kind": "waf-payload-probe", "base": url, "baseline": None, "probes": [], "trip": None}
    st, hd, rh, body, err = fetch(url, timeout=12)
    obs["baseline"] = {"status": st, "error": err, "size": len(body) if body else None}
    print(f"[*] baseline {url} -> status={st} err={err}")
    if err or st is None:
        print("[!] 기준 요청 실패 — 프로브 중단(transport 실패는 WAF 차단과 별도 클래스)", file=sys.stderr)
        return obs

    base = url + ("&" if "?" in url else "?") + "x="
    for payload in BENIGN_PAYLOADS:
        st, hd, rh, body, err = fetch(base + payload, timeout=12)
        rec = {"payload": payload[:30], "status": st, "error": err,
               "size": len(body) if body else None}
        obs["probes"].append(rec)
        blocked = (st in BLOCK_STATUS) or (err is not None)
        if blocked:
            obs["trip"] = rec
            print(f"[!] 차단 신호 감지 status={st} err={err} — 즉시 중단, 사람 보고 필요")
            break
        print(f"[.] probe status={st} size={rec['size']}")
        time.sleep(0.3)

    if obs["trip"] and obs["baseline"].get("status") not in BLOCK_STATUS:
        trip = obs["trip"]
        _bind_finding(obs, odir, target, recon_id, "waf-payload", {
            "asset_kind": "defense",
            "product": "waf",
            "version": "unknown",
            "version_bound": "UNSET",
            "provenance": "inferred",
            "evidence_quote": f'"payload": "{trip["payload"]}"',
            "reasoning": f"waf-payload-probe({recon_id}): 페이로드에 대한 차단 반응(status={trip['status']}) — "
                         "WAF/IPS 존재 inferred. 트립 → 즉시 중단·사람 보고",
            "verified_by": [f"waf_recon.py:payload:{recon_id}"],
            "http_status": trip["status"],
        })
    return obs


def probe_rate_limit(url, target, recon_id, n):
    """baseline 대비 N 요청 후 429/드롭 관찰."""
    odir = os.path.join(ROOT, "targets", target, "captures", "observation")
    os.makedirs(odir, exist_ok=True)
    statuses = []
    st, hd, rh, body, err = fetch(url, timeout=12)
    statuses.append({"seq": 0, "status": st, "error": err})
    for i in range(1, n + 1):
        st, hd, rh, body, err = fetch(url, timeout=8)
        statuses.append({"seq": i, "status": st, "error": err})
        time.sleep(0.05)
    blocked = [r for r in statuses[1:] if r["status"] == 429 or (r["error"] and "reset" in (r["error"] or "").lower())]
    obs = {"kind": "rate-limit", "n": n, "statuses": statuses, "blocked": len(blocked)}
    if blocked:
        b = blocked[0]
        _bind_finding(obs, odir, target, recon_id, "waf-ratelimit", {
            "asset_kind": "defense",
            "product": "ratelimit",
            "version": "unknown",
            "version_bound": "UNSET",
            "provenance": "inferred",
            "evidence_quote": f'"status": {b["status"]}',
            "reasoning": f"rate-limit probe({recon_id}): 연속 {b['seq']}번째 요청에서 429/드롭 — 레이트리밋 inferred",
            "verified_by": [f"waf_recon.py:rate:{recon_id}"],
        })
    return obs


def main() -> int:
    _utf8_stdio()
    ap = argparse.ArgumentParser(description="Defense posture probe (WAF/IPS/ratelimit) — needs GO")
    ap.add_argument("--url", required=True, help="프로브 대상 URL (예: https://lab.example/)")
    ap.add_argument("--ip", required=True, help="스코프 검사용 IP")
    ap.add_argument("--target", required=True, help="host label (targets/<host>/)")
    ap.add_argument("--recon-id", required=True)
    ap.add_argument("--approved", action="store_true")
    ap.add_argument("--wafw00f", action="store_true", help="wafw00f 실행")
    ap.add_argument("--payloads", action="store_true", help="소량 벤치 페이로드 프로브")
    ap.add_argument("--rate", type=int, default=0, help="레이트리밋 프로브 요청 수(0=off)")
    args = ap.parse_args()

    if not args.approved:
        print(f"[STOP] 능동 정찰입니다. 사람의 `GO {args.recon_id}` 승인 후 --approved 로 재실행하세요.",
              file=sys.stderr)
        return 3
    if not scope_allows(args.ip):
        print(f"[STOP] {args.ip} 은(는) scope.md 허용 대역 밖입니다.", file=sys.stderr)
        return 3
    if not (args.wafw00f or args.payloads or args.rate > 0):
        print("[!] --wafw00f / --payloads / --rate 중 하나 이상 지정", file=sys.stderr)
        return 2

    odir = os.path.join(ROOT, "targets", args.target, "captures", "observation")
    os.makedirs(odir, exist_ok=True)

    if args.wafw00f:
        run_wafw00f(args.url, args.target, args.recon_id)
    if args.payloads:
        obs = probe_payloads(args.url, args.target, args.recon_id)
        with open(os.path.join(odir, f"waf-payload-{args.recon_id}.json"), "w", encoding="utf-8") as f:
            json.dump(obs, f, indent=2, ensure_ascii=False)
    if args.rate > 0:
        obs_rl = probe_rate_limit(args.url, args.target, args.recon_id, args.rate)
        with open(os.path.join(odir, f"waf-ratelimit-{args.recon_id}.json"), "w", encoding="utf-8") as f:
            json.dump(obs_rl, f, indent=2, ensure_ascii=False)

    print(f"\n[*] 완료. 재검증/확정 후 게이트: npm run check -- {args.target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
