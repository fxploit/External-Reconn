#!/usr/bin/env python3
"""vhost 발견 러너 (능동 정찰 — RUN 단계)

같은 IP 가 Host 헤더로 여러 가상호스트를 서빙하면, 워드리스트의 후보 Host 로 요청을 보내
'기준 응답(baseline)'과의 차이로 숨은 vhost 를 판별한다.

오탐(와일드카드 vhost) 억제:
 - 무작위 vhost 를 기준선(baseline)으로 삼고, 후보 응답이 기준선과
   상태코드/본문크기/본문해시 어느 하나라도 유의미하게 다를 때만 후보로 잡는다.
 - 결정 판정은 스크립트가 내리지 않는다. 결과는 Observation 으로만 보존하고,
   사람이 확인한 뒤 기존 수집기로 재수집한다:
     collect_spa.py --host-map vhost=ip   /   collect_web.py --host vhost

⚠️ 능동 정찰이다. 사람의 `GO <recon_id>` 승인 없이 실행하면 안 된다.
    --recon-id 와 --approved 두 인자를 모두 줘야만 실제 요청을 보낸다(기본 차단).

Usage:
    python scripts/discover_vhost.py 10.10.110.5 --target intranet.corp.htb --recon-id RECON-01 --approved
    python scripts/discover_vhost.py 10.10.110.5 --target 10.10.110.5 --recon-id RECON-01 --approved \
        --wordlist wordlists/vhosts.txt --port 80 --diff-threshold 50
"""
import argparse
import hashlib
import json
import os
import random
import re
import string
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect_web import fetch, now_iso  # noqa: E402

DEFAULT_WORDLIST = [
    "admin", "api", "app", "autodiscover", "beta", "blog", "cms", "dashboard",
    "dev", "docker", "files", "ftp", "git", "gitlab", "intranet", "jenkins",
    "jira", "mail", "management", "monitor", "owa", "portal", "prod", "production",
    "sso", "stage", "staging", "test", "tests", "vpn", "webmail", "www", "www2",
]


def _utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def random_vhost() -> str:
    return "".join(random.choices(string.ascii_lowercase, k=14)) + ".invalid"


def result_key(status, body: bytes) -> tuple:
    return (status, len(body), hashlib.sha256(body).hexdigest())


def scope_allows(ip):
    """scope.md 허용 대역 밖이면 False. UNSET/파싱 불가는 False."""
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


def main() -> int:
    _utf8_stdio()
    ap = argparse.ArgumentParser(description="Active vhost discovery (needs human GO)")
    ap.add_argument("ip", help="대상 IP")
    ap.add_argument("--target", required=True, help="host label (targets/<host>/)")
    ap.add_argument("--recon-id", required=True, help="GO 승인된 recon_id (예: RECON-01)")
    ap.add_argument("--approved", action="store_true",
                    help="사람의 GO <recon-id> 승인을 받았음을 명시(없으면 실행 차단)")
    ap.add_argument("--wordlist", default=None, help="후보 vhost 워드리스트 파일(줄마다 하나)")
    ap.add_argument("--domain", default=None,
                    help="베이스 도메인(T19#3): 워드리스트의 bare label 을 word.domain 으로 Host 후보 생성. "
                         "항목이 이미 FQDN(점 포함)이면 그대로 사용")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--scheme", default="http", choices=["http", "https"])
    ap.add_argument("--timeout", type=int, default=8)
    ap.add_argument("--diff-threshold", type=int, default=40,
                    help="본문 크기 차이 기준(바이트) — 이보다 작은 변화는 오탐으로 취급")
    args = ap.parse_args()

    # ── GO 게이트: 승인 없이는 어떤 네트워크 요청도 보내지 않는다 ──────────────
    if not args.approved:
        print(
            "[STOP] 능동 정찰입니다. 사람의 `GO " + args.recon_id + "` 승인 후 --approved 로 재실행하세요.\n"
            "       (도구 파일·명령 초안은 GO 이전에 준비할 수 있으나, 실행은 GO 뒤에만 합니다)",
            file=sys.stderr,
        )
        return 3

    # ── 스코프 게이트: 허용 대역 밖이면 요청 전에 STOP ───────────────────────
    if not scope_allows(args.ip):
        print("[STOP] " + args.ip + " 은(는) scope.md 허용 대역 밖입니다. 정찰을 시작하지 않습니다.",
              file=sys.stderr)
        return 3

    candidates = []
    if args.wordlist:
        if not os.path.exists(args.wordlist):
            print(f"[!] wordlist not found: {args.wordlist}", file=sys.stderr)
            return 2
        with open(args.wordlist, encoding="utf-8", errors="replace") as f:
            candidates = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    else:
        candidates = DEFAULT_WORDLIST
    if not candidates:
        print("[!] 워드리스트가 비어 있습니다", file=sys.stderr)
        return 2
    # T19#3: --domain 지정 시 bare label 을 FQDN 후보로 확장(이미 점이 있으면 그대로)
    if args.domain:
        dom = args.domain.strip(".")
        candidates = [c if "." in c else f"{c}.{dom}" for c in candidates]

    # HTTPS vhost 는 파이썬 폴백(fetch)이 SNI 를 못 보내므로 오탐 가능 — 경고 (T13)
    if args.scheme == "https":
        print("[!] https vhost 는 SNI 처리가 필요해 파이썬 폴백이 부정확할 수 있습니다. "
              "gobuster vhost(컨테이너) 경로를 권장합니다.", file=sys.stderr)

    base_url = f"{args.scheme}://{args.ip}:{args.port}/"
    obs = {
        "recon_id": args.recon_id,
        "kind": "vhost-discovery",
        "target": args.target,
        "command": f"python scripts/discover_vhost.py {args.ip} --target {args.target} --recon-id {args.recon_id}",
        "started_at": now_iso(),
        "base_url": base_url,
        "baseline": None,
        "candidates_tested": 0,
        "candidates_found": [],
        "detail": [],
    }

    # ── 기준선: 무작위 vhost 응답(와일드카드 오탐 억제용) ──────────────────────
    base_host = random_vhost()
    st, hd, rh, body, err = fetch(base_url, args.timeout, host=base_host)
    obs["baseline"] = {
        "random_vhost": base_host,
        "status": st,
        "error": err,
        "size": len(body) if body else None,
        "sha256": hashlib.sha256(body).hexdigest() if body else None,
    }
    print(f"[*] baseline(random vhost) host={base_host} status={st} size={len(body) if body else None}")
    if err:
        print(f"[!] 기준선 요청 실패: {err} — 대상이 HTTP vhost 응답을 안 줄 수 있습니다", file=sys.stderr)

    # ── 후보 탐색 ───────────────────────────────────────────────────────────
    for host in candidates:
        st, hd, rh, body, err = fetch(base_url, args.timeout, host=host)
        rec = {"host": host, "status": st, "error": err,
               "size": len(body) if body else None,
               "sha256": hashlib.sha256(body).hexdigest() if body else None}
        obs["candidates_tested"] += 1
        time.sleep(0.05)

        found = False
        reason = None
        if err:
            reason = f"요청 오류: {err}"
        elif obs["baseline"]["error"]:
            # 기준선이 실패했는데 후보가 응답하면(성공이면) 유효 vhost 후보
            if st is not None:
                found, reason = True, "기준선(오류)과 달리 정상 응답"
        else:
            b = obs["baseline"]
            if st != b["status"]:
                found, reason = True, f"상태코드 다름 (baseline {b['status']} vs {st})"
            elif b["size"] is not None and rec["size"] is not None and \
                    abs(rec["size"] - b["size"]) >= args.diff_threshold:
                found, reason = True, f"본문크기 차이 {rec['size'] - b['size']} bytes"
            elif rec["sha256"] and rec["sha256"] != b["sha256"]:
                found, reason = True, "본문 내용 다름"
        rec["found"] = found
        rec["reason"] = reason
        obs["detail"].append(rec)
        if found:
            obs["candidates_found"].append(rec)
            print(f"[+] vhost 후보: {host}  ({reason})")

    obs["finished_at"] = now_iso()

    # ── Observation 보존 (실패·미매칭 삭제 금지) ──────────────────────────────
    odir = os.path.join(ROOT, "targets", args.target, "captures", "observation")
    os.makedirs(odir, exist_ok=True)
    opath = os.path.join(odir, f"vhost-{args.recon_id}.json")
    with open(opath, "w", encoding="utf-8") as f:
        json.dump(obs, f, indent=2, ensure_ascii=False)

    print(f"\n[*] 테스트 {obs['candidates_tested']}건, 후보 {len(obs['candidates_found'])}건")
    print(f"[*] Observation: {os.path.relpath(opath, ROOT)}")
    print("[*] 후보 vhost 는 사람이 확인 후 재수집하세요:")
    for c in obs["candidates_found"]:
        print(f"      python scripts/collect_spa.py http://{c['host']}/ --target {c['host']}"
              f" --host-map {c['host']}={args.ip}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
