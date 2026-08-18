#!/usr/bin/env python3
"""서브도메인·DNS 발견 (T17) — vhost(T4)와 상보적, DNS 레벨 자산.

- passive: 수집 자산(js/css/html)에서 <base> 도메인을 포함한 호스트 문자열을 추출한다(저위험).
  추출된 문자열의 '존재'는 confirmed(자산에 바이트 실재), '실사용 호스트 여부'는 inferred.
- active: 워드리스트 기반 서브도메인 DNS 해석(dig/gethostbyname).
  ⚠️ 능동 정찰 — `GO <recon_id>` + `--approved` + 스코프 게이트 없이는 실행하지 않는다.
  해석된 IP 가 scope.md 허용 대역 밖이면 기록만 하고 후속 수집하지 않는다(자동 확장 금지).

Usage:
    python scripts/discover_dns.py corp.htb --target 10.10.110.5 --passive
    python scripts/discover_dns.py corp.htb --target 10.10.110.5 --active \
        --recon-id RECON-03 --approved --wordlist wordlists/subdomains.txt
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib.engagement import go_approval, stamp_findings  # noqa: E402

DOMAIN_RE = re.compile(r"(?<![A-Za-z0-9.-])([a-z0-9][a-z0-9-]{0,62}\.)+")


def _utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def scope_allows(ip):
    """scope.md 허용 대역 밖이면 False."""
    spath = os.path.join(ROOT, "scope.md")
    if not os.path.exists(spath):
        return False
    with open(spath, encoding="utf-8") as f:
        content = f.read()
    content = re.sub(r"<!--[\s\S]*?-->", "", content)  # 주석 예시 대역 활성화 방지(T19#5)
    m = re.search(r"허용 대역:\s*(.+)", content)
    if not m or "UNSET" in m.group(1):
        return False
    ranges = [r.strip() for r in m.group(1).split(",") if r.strip()]

    def ip_int(ip):
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        try:
            nums = [int(p) for p in parts]
        except ValueError:
            return None
        if any(n < 0 or n > 255 for n in nums):
            return None
        return (nums[0] << 24) + (nums[1] << 16) + (nums[2] << 8) + nums[3]

    def in_cidr(ip, cidr):
        net, _, bits = cidr.partition("/")
        b = int(bits) if bits else 32
        a, n = ip_int(ip), ip_int(net)
        if a is None or n is None or b < 0 or b > 32:
            return False
        if b == 0:
            return True
        mask = (0xFFFFFFFF << (32 - b)) & 0xFFFFFFFF
        return (a & mask) == (n & mask)

    return any(in_cidr(ip, r) for r in ranges)


def find_under_domain(text, base):
    """base 도메인 아래의 호스트 문자열(단순 문자열, 유효성 판단 안 함)."""
    base = base.lower().strip(".")
    found = set()
    for m in re.finditer(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?\." + re.escape(base) + r"\b", text.lower()):
        found.add(m.group(0))
    return sorted(found)


def passive(host, base):
    """수집 자산에서 base 도메인 포함 호스트 문자열 추출 → finding(존재 confirmed)."""
    fpath = os.path.join(ROOT, "targets", host, "findings.json")
    mpath = os.path.join(ROOT, "targets", host, "captures", "manifest.json")
    if not os.path.exists(fpath) or not os.path.exists(mpath):
        print(f"[!] findings/manifest 없음 — collect_web.py 먼저 실행", file=sys.stderr)
        return 2
    with open(fpath, encoding="utf-8") as f:
        doc = json.load(f)
    with open(mpath, encoding="utf-8") as f:
        manifest = json.load(f)

    odir = os.path.join(ROOT, "targets", host, "captures", "observation")
    os.makedirs(odir, exist_ok=True)
    obs = {"kind": "dns-passive", "base": base, "found": [], "per_asset": []}

    findings = doc.get("findings", [])
    existing = {(f.get("evidence_path"), f.get("evidence_quote")) for f in findings}
    fid_base = max([int(x["finding_id"].split("-")[-1]) for x in findings] or [0])

    for asset in manifest.get("assets", []):
        ref = asset.get("raw_ref")
        kind = asset.get("asset_kind")
        if kind not in ("js", "css", "html") or not ref or not os.path.exists(os.path.join(ROOT, ref)):
            continue
        with open(os.path.join(ROOT, ref), "rb") as f:
            text = f.read().decode("utf-8", "replace")
        found = find_under_domain(text, base)
        if not found:
            continue
        sha = asset.get("asset_sha256")
        obs["per_asset"].append({"asset": ref, "hosts": found})
        for d in found:
            obs["found"].append(d)
            key = (ref, d)
            if key in existing:
                continue
            existing.add(key)
            fid_base += 1
            findings.append({
                "finding_id": f"FND-{fid_base:03d}",
                "asset_kind": kind,
                "product": "dns:subdomain",
                "version": "unknown",
                "version_bound": "UNSET",
                "provenance": "confirmed",
                "evidence_path": ref,
                "evidence_quote": d,
                "asset_sha256": sha,
                "reasoning": f"discover_dns(passive): 자산에 '{d}' 문자열 실재(confirmed) — 실사용 호스트 여부는 미확인(inferred)",
                "verified_by": ["discover_dns.py:passive"],
                "report_eligible": False,
            })

    obs["found"] = sorted(set(obs["found"]))
    opath = os.path.join(odir, f"dns-passive-{base}.json")
    with open(opath, "w", encoding="utf-8") as f:
        json.dump(obs, f, indent=2, ensure_ascii=False)
    stamp_findings(findings, "discover_dns.py:passive")
    doc["findings"] = findings
    stamp_findings(findings, "discover_dns.py:active")
    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)

    print(f"[*] passive: {len(obs['found'])}개 호스트 문자열 발견")
    for d in obs["found"]:
        print(f"    {d}")
    print(f"[*] Observation: {os.path.relpath(opath, ROOT)}")
    print("[*] 게이트 확인: npm run check -- " + host)
    return 0


def active(host, base, recon_id, approved, wordlist):
    """워드리스트 DNS 브루트(능동). GO+approved+스코프 게이트."""
    if not approved:
        print(f"[STOP] 능동 정찰입니다. 사람의 `GO {recon_id}` 승인 후 --approved 로 재실행하세요.",
              file=sys.stderr)
        return 3
    go_approval(host, recon_id, " ".join(sys.argv), {"base": base})
    candidates = []
    if wordlist and os.path.exists(wordlist):
        with open(wordlist, encoding="utf-8", errors="replace") as f:
            candidates = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    else:
        candidates = ["www", "api", "admin", "dev", "staging", "intranet", "mail",
                      "vpn", "git", "jenkins", "portal", "sso", "db", "internal"]
    dig = shutil.which("dig")
    odir = os.path.join(ROOT, "targets", host, "captures", "observation")
    os.makedirs(odir, exist_ok=True)
    lines = []

    results = []
    for sub in candidates:
        fqdn = f"{sub}.{base}"
        if dig:
            r = subprocess.run([dig, "+short", fqdn], capture_output=True, text=True, timeout=10)
            out = r.stdout.strip()
        else:
            try:
                import socket
                out = socket.gethostbyname(fqdn)
            except Exception:
                out = ""
        if not out:
            continue
        ips = [ln.strip() for ln in out.splitlines() if ln.strip() and not ln.startswith(";")]
        if not ips:
            continue
        lines.append(f"{fqdn} -> {', '.join(ips)}")
        rec = {"fqdn": fqdn, "ips": ips,
               "in_scope": any(scope_allows(ip) for ip in ips)}
        results.append(rec)
        tag = "in-scope" if rec["in_scope"] else "OUT-OF-SCOPE(기록만)"
        print(f"[+] {fqdn:40s} -> {', '.join(ips)} [{tag}]")

    obs_txt = "\n".join(lines) + "\n"
    txt_path = os.path.join(odir, f"dns-active-{recon_id}.txt")
    with open(txt_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(obs_txt)
    meta_path = os.path.join(odir, f"dns-active-{recon_id}.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump({"recon_id": recon_id, "kind": "dns-active", "base": base,
                   "results": results, "finished_at": now_iso()}, f, indent=2, ensure_ascii=False)

    # 해석 결과를 confirmed finding 으로 (근거: 도구 출력 파일 실재)
    fpath = os.path.join(ROOT, "targets", host, "findings.json")
    doc = {"findings": []}
    if os.path.exists(fpath):
        with open(fpath, encoding="utf-8") as f:
            doc = json.load(f)
    findings = doc.get("findings", [])
    existing = {(f.get("evidence_path"), f.get("evidence_quote")) for f in findings}
    data = open(txt_path, "rb").read()
    import hashlib
    sha = hashlib.sha256(data).hexdigest()
    fid_base = max([int(x["finding_id"].split("-")[-1]) for x in findings] or [0])
    for rec in results:
        quote = f"{rec['fqdn']} -> {', '.join(rec['ips'])}"
        key = (os.path.relpath(txt_path, ROOT).replace("\\", "/"), quote)
        if key in existing:
            continue
        existing.add(key)
        fid_base += 1
        findings.append({
            "finding_id": f"FND-{fid_base:03d}",
            "asset_kind": "dns",
            "product": "dns:host",
            "version": ", ".join(rec["ips"]),
            "version_bound": "UNSET",
            "provenance": "confirmed",
            "evidence_path": os.path.relpath(txt_path, ROOT).replace("\\", "/"),
            "evidence_quote": quote,
            "asset_sha256": sha,
            "reasoning": (f"discover_dns(active): {rec['fqdn']} 가 DNS 로 해석됨 — 도구 출력 실재(confirmed). "
                          f"스코프={'in' if rec['in_scope'] else 'OUT'} — 밖이면 기록만"),
            "verified_by": [f"discover_dns.py:active:{recon_id}"],
            "report_eligible": False,
        })
    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)

    print(f"\n[*] 해석 {len(results)}건 / Observation: {os.path.relpath(txt_path, ROOT)}")
    print("[*] in-scope 호스트만 후속 수집 권장(대역 밖은 자동 확장 금지)")
    return 0


def main() -> int:
    _utf8_stdio()
    ap = argparse.ArgumentParser(description="Subdomain/DNS discovery")
    ap.add_argument("base", help="베이스 도메인 (예: corp.htb)")
    ap.add_argument("--target", required=True, help="host label (targets/<host>/)")
    ap.add_argument("--passive", action="store_true", help="수집 자산에서 호스트 문자열 추출(저위험)")
    ap.add_argument("--active", action="store_true", help="DNS 브루트(능동 — GO 필요)")
    ap.add_argument("--recon-id", default="", help="GO 승인된 recon_id (active)")
    ap.add_argument("--approved", action="store_true", help="사람의 GO 승인 확인 (active)")
    ap.add_argument("--wordlist", default=None, help="서브도메인 워드리스트")
    args = ap.parse_args()

    if args.passive:
        return passive(args.target, args.base)
    if args.active:
        return active(args.target, args.base, args.recon_id, args.approved, args.wordlist)
    print("[!] --passive 또는 --active 중 하나를 지정하세요", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
