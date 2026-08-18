#!/usr/bin/env python3
"""능동 정찰 러너 — 포트/서비스 스캔(nmap) + 디렉터리 열거(능동, RUN 단계)

각 실행의 stdout/stderr/exit code/명령/타임스탬프를 captures/observation/ 에 보존하고,
서비스 배너/버전은 결정론적 도구(nmap) 원본 출력을 근거로 provenance=confirmed 후보를
findings.json 에 반영한다(배너 원문을 evidence 로 바인딩).

⚠️ 능동 정찰이다. 사람의 `GO <recon_id>` 승인 없이 실행하면 안 된다.
    --recon-id 와 --approved 를 모두 줘야 실행한다. 또한 타깃 IP 가 scope.md 허용 대역
    밖이면 요청을 보내기 전에 STOP 한다.

Usage:
    python scripts/active_recon.py 10.10.110.5 --target 10.10.110.5 --recon-id RECON-02 --approved
    python scripts/active_recon.py 10.10.110.5 --target 10.10.110.5 --recon-id RECON-02 --approved \
        --nmap-args "-sV -p 22,80,443,8080" --dir-enum --wordlist wordlists/dirs.txt
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect_web import now_iso  # noqa: E402

DEFAULT_DIRS = [
    "admin", "api", "assets", "backup", "config", "console", "css", "data",
    "docs", "downloads", "images", "img", "index.php", "js", "login", "logs",
    "old", "phpmyadmin", "robots.txt", "static", "uploads", "vendor", "wp-admin",
    "wp-content", "wp-includes", "www",
]

# ── 서버사이드 프로브 (T12) ───────────────────────────────────────────────────
# 기본 프로브 + 제품 힌트가 있을 때의 프로브. 응답을 자산으로 저장하면 fingerprint 가
# 시그니처(마커)와 해시 DB(Django admin css)를 그대로 적용한다.
DEFAULT_PROBES = [
    ("robots.txt", "/robots.txt", "html"),
    ("error404", "/__recon_404_probe__/", "html"),
]
PRODUCT_PROBES = {
    "Django": [("django-admin-login", "/admin/login/", "html"),
               ("django-admin-base", "/static/admin/css/base.css", "css")],
    "WordPress": [("wp-login", "/wp-login.php", "html"),
                  ("wp-json", "/wp-json/", "html")],
    "Flask": [],
    "Werkzeug": [],
}


def _utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


# ── scope 검사 (게이트와 동일한 CIDR 로직) ─────────────────────────────────────
def ip_to_int(ip):
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
    net, _, bits_raw = cidr.partition("/")
    bits = int(bits_raw) if bits_raw else 32
    ip_int, net_int = ip_to_int(ip), ip_to_int(net)
    if ip_int is None or net_int is None or bits < 0 or bits > 32:
        return False
    if bits == 0:
        return True
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return (ip_int & mask) == (net_int & mask)


def scope_allows(ip):
    """scope.md 허용 대역 밖이면 False(호출부가 STOP). UNSET/파싱 불가는 False."""
    spath = os.path.join(ROOT, "scope.md")
    if not os.path.exists(spath):
        return False
    with open(spath, encoding="utf-8") as f:
        content = f.read()
    content = re.sub(r"<!--[\s\S]*?-->", "", content)  # 주석 예시 대역 활성화 방지(T19#5)
    m = re.search(r"허용 대역:\s*(.+)", content)
    if not m:
        return False
    line = m.group(1).strip()
    if line == "UNSET" or "UNSET" in line:
        return False
    ranges = [r.strip() for r in line.split(",") if r.strip()]
    if not ranges:
        return False
    return any(in_cidr(ip, r) for r in ranges)


# ── 실행 보존 ────────────────────────────────────────────────────────────────
def run_and_capture(cmd, out_stem, recon_id, target):
    odir = os.path.join(ROOT, "targets", target, "captures", "observation")
    os.makedirs(odir, exist_ok=True)
    txt_path = os.path.join(odir, f"{out_stem}-{recon_id}.txt")
    meta_path = os.path.join(odir, f"{out_stem}-{recon_id}.json")
    print(f"[*] 실행: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=600)
        stdout = proc.stdout.decode("utf-8", "replace")
        stderr = proc.stderr.decode("utf-8", "replace")
        rc = proc.returncode
    except FileNotFoundError as e:
        stdout, stderr, rc = "", f"도구 없음: {e}", 127
    except subprocess.TimeoutExpired:
        stdout, stderr, rc = "", "timeout 600s", 124

    with open(txt_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(stdout)
        if stderr:
            f.write("\n--- stderr ---\n" + stderr)
    meta = {
        "recon_id": recon_id,
        "command": cmd,
        "stdout_ref": os.path.relpath(txt_path, ROOT).replace("\\", "/"),
        "exit_code": rc,
        "stderr_tail": stderr[-2000:],
        "started_at": now_iso(),
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    print(f"[*] stdout/stderr/exit={rc} -> {os.path.relpath(txt_path, ROOT)}")
    return stdout, stderr, rc, meta


# ── findings 반영 ────────────────────────────────────────────────────────────
def parse_banner(service, detail):
    """nmap 배너 라인에서 product/version 을 토큰 단위로 분리 (T13 정밀화).

    예: "nginx 1.18.0 (Ubuntu)" → (nginx, 1.18.0, confirmed)
        "SimpleHTTPServer 0.6 (Python 3.12.3)" → (SimpleHTTPServer, 0.6, confirmed)
        "Apache httpd" → (apache-httpd, unknown, False)  # 버전 미상 → inferred
    """
    tokens = detail.split()
    version = None
    for t in tokens:
        if re.search(r"\d+\.\d+(?:\.\d+)?", t):
            version = t.strip("()")
            break
    prod = None
    for t in tokens:
        if t and re.match(r"^[A-Za-z][A-Za-z0-9_-]*$", t) and t.lower() not in (
                "version", "ubuntu", "debian", "linux"):
            prod = t
            break
    if prod is None:
        prod = service
    return prod, version or "unknown", version is not None


def banner_findings_from_stdout(stdout, out_stem, recon_id, target, kind_prefix):
    """nmap/gobuster 출력에서 배너/버전 줄을 confirmed 후보로 추출해 findings.json 에 추가.

    근거는 '실제 저장된 도구 출력 파일'에 바인딩한다(게이트가 바이트 재검증).
    """
    odir = os.path.join(ROOT, "targets", target, "captures", "observation")
    txt_path = os.path.join(odir, f"{out_stem}-{recon_id}.txt")
    if not os.path.exists(txt_path):
        return 0
    data = open(txt_path, "rb").read()
    import hashlib
    sha = hashlib.sha256(data).hexdigest()

    lines = [ln for ln in stdout.splitlines() if ln.strip()]
    added = 0
    if kind_prefix == "nmap" and lines:
        # nmap -sV 서비스 라인 예: "80/tcp open  http nginx 1.18.0"
        for ln in lines:
            m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?$", ln)
            if not m:
                continue
            port, service, detail = m.group(1), m.group(2), (m.group(3) or "").strip()
            prod, version, has_ver = parse_banner(service, detail)
            quote = ln
            if quote.encode("utf-8") not in data:
                continue
            append_finding(target, {
                "asset_kind": "service",
                "product": prod,
                "version": version,
                "version_bound": "UNSET",
                "provenance": "confirmed" if has_ver else "inferred",
                "evidence_path": os.path.relpath(txt_path, ROOT).replace("\\", "/"),
                "evidence_quote": quote,
                "asset_sha256": sha,
                "reasoning": f"nmap({out_stem}): 포트 {port} 서비스 배너 원문 — 도구 출력에 실재"
                             + ("(정확 버전)" if has_ver else "(버전 미상 → inferred)"),
                "verified_by": [f"active_recon.py:{out_stem}"],
            })
            added += 1
    elif kind_prefix == "dir" and lines:
        # gobuster dir 출력 예: "/admin (Status: 200) [Size: 1234]"
        for ln in lines:
            m = re.match(r"^(\S+)\s+\(Status:\s*(\d+)\)", ln)
            if not m or m.group(2) in ("403", "404"):
                continue
            quote = ln
            if quote.encode("utf-8") not in data:
                continue
            # T19#4: 경로 발견은 (product, version) 스키마를 오염시키지 않는다 — CVE 하네스가
            # (product, version)으로 조회할 때 http-path/status 가 섞이지 않게 UNSET + http_status 필드.
            append_finding(target, {
                "asset_kind": "path",
                "product": "UNSET",
                "version": "UNSET",
                "version_bound": "UNSET",
                "provenance": "inferred",
                "evidence_path": os.path.relpath(txt_path, ROOT).replace("\\", "/"),
                "evidence_quote": quote,
                "asset_sha256": sha,
                "reasoning": f"디렉터리 열거({out_stem}): {m.group(1)} status={m.group(2)} — 존재/사용은 미확인",
                "verified_by": [f"active_recon.py:{out_stem}"],
                "http_status": int(m.group(2)),
            })
            added += 1
    return added


def append_finding(target, finding):
    fpath = os.path.join(ROOT, "targets", target, "findings.json")
    if not os.path.exists(fpath):
        return
    with open(fpath, encoding="utf-8") as f:
        doc = json.load(f)
    findings = doc.setdefault("findings", [])
    nums = [int(x["finding_id"].split("-")[-1]) for x in findings if x["finding_id"].split("-")[-1].isdigit()]
    fid = max(nums or [0]) + 1
    finding["finding_id"] = f"FND-{fid:03d}"
    finding["report_eligible"] = False
    findings.append(finding)
    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    print(f"[+] finding FND-{fid:03d}: {finding['product']} {finding['version']} ({finding['provenance']})")


def dir_enum_fallback(ip, port, scheme, target, recon_id, wordlist):
    """gobuster 없을 때 순수 파이썬 폴백 — 저부하 디렉터리 열거(상태 코드 기준)."""
    from collect_web import fetch
    found = []
    for path in wordlist:
        url = f"{scheme}://{ip}:{port}/{path}"
        st, hd, rh, body, err = fetch(url, timeout=6)
        if err:
            continue
        if st not in (200, 301, 302, 307, 308, 401, 403):
            continue
        found.append(f"/{path} (Status: {st}) [Size: {len(body)}]")
    return "\n".join(found)


def server_probe(target, ip, port, scheme, recon_id, host=None):
    """서버사이드 프로브 (T12) — 기본 경로/에러 유발로 드러나는 지문을 능동 수집.

    각 프로브 응답을 raw 자산으로 저장·manifest 에 등록하면, fingerprint.py 가 시그니처
    마커(Django admin login, wp-login 등)와 해시 DB(Django admin css → 버전)를 그대로 적용한다.
    파괴적 동작·인증 우회는 없음(GET 조회만). 결과는 Observation 에 보존.
    host 가 주어지면(HTTPS vhost/SNI) URL 은 호스트명으로, 스코프 검사는 ip 로.
    """
    from collect_web import fetch, kind_for, rel, safe_name, sha256_hex, now_iso

    fpath = os.path.join(ROOT, "targets", target, "findings.json")
    products = set()
    if os.path.exists(fpath):
        with open(fpath, encoding="utf-8") as f:
            doc = json.load(f)
        products = {x.get("product") for x in doc.get("findings", []) if x.get("product")}

    probes = list(DEFAULT_PROBES)
    for p in products:
        probes.extend(PRODUCT_PROBES.get(p, []))

    mpath = os.path.join(ROOT, "targets", target, "captures", "manifest.json")
    manifest = {"assets": []}
    if os.path.exists(mpath):
        with open(mpath, encoding="utf-8") as f:
            manifest = json.load(f)
    raw_dir = os.path.join(ROOT, "targets", target, "captures", "raw")
    os.makedirs(raw_dir, exist_ok=True)

    idx = len([a for a in manifest.get("assets", []) if a.get("raw_ref")])
    results = []
    base = f"{scheme}://{host or ip}:{port}"
    for name, path, hint_kind in probes:
        url = base + path
        st, hd, rh, body, err = fetch(url, timeout=10)
        if err or st is None or st >= 400:
            results.append({"probe": name, "url": url, "status": st, "error": err})
            continue
        kind = kind_for(url, hd.get("Content-Type", "")) or hint_kind
        idx += 1
        fname = safe_name(url, idx, kind)
        with open(os.path.join(raw_dir, fname), "wb") as f:
            f.write(body)
        manifest.setdefault("assets", []).append({
            "asset_id": f"AST-{idx:03d}",
            "source_url": url,
            "asset_kind": kind,
            "http_status": st,
            "content_type": hd.get("Content-Type", ""),
            "raw_ref": rel(os.path.join(raw_dir, fname)),
            "asset_sha256": sha256_hex(body),
        })
        results.append({"probe": name, "url": url, "status": st, "asset": rel(os.path.join(raw_dir, fname))})
        print(f"[+] probe {name:24s} {st} {url} -> {rel(os.path.join(raw_dir, fname))}")

    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    # Observation 보존
    odir = os.path.join(ROOT, "targets", target, "captures", "observation")
    os.makedirs(odir, exist_ok=True)
    opath = os.path.join(odir, f"server-probe-{recon_id}.json")
    with open(opath, "w", encoding="utf-8") as f:
        json.dump({"recon_id": recon_id, "kind": "server-probe", "results": results,
                   "hinted_products": sorted(products), "finished_at": now_iso()}, f,
                  indent=2, ensure_ascii=False)
    print(f"[*] probe 결과 Observation: {os.path.relpath(opath, ROOT)}")

    # 수집된 프로브 자산에 시그니처/해시 DB 적용 (fingerprint 재실행)
    print("[*] fingerprint 재실행(프로브 자산 매칭)...")
    subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "fingerprint.py"), target],
                   cwd=ROOT, capture_output=True)
    return len(results)


def candidate_probe(target, ip, port, scheme, recon_id, candidate_file, host=None):
    """Fetch parser output only after GO; candidate parsing itself makes no requests."""
    from collect_web import fetch
    base = f"{scheme}://{host or ip}:{port}"
    entries = []
    found = []
    with open(candidate_file, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#") or "\t" not in line:
                continue
            source, value = line.rstrip("\n").split("\t", 1)
            parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(value)
            if parsed.scheme and parsed.netloc and parsed.netloc != (host or ip):
                entries.append({"source": source, "url": value, "status": "STOP_EXTERNAL_NOT_FETCHED"})
                continue
            url = value if parsed.scheme else base + (value if value.startswith("/") else "/" + value)
            st, _hd, _rh, body, err = fetch(url, timeout=10, host=host)
            entries.append({"source": source, "url": url, "status": st, "error": err})
            if err or st is None:
                continue
            odir = os.path.join(ROOT, "targets", target, "captures", "observation")
            os.makedirs(odir, exist_ok=True)
            out = os.path.join(odir, f"candidate-paths-{recon_id}.txt")
            with open(out, "a", encoding="utf-8", newline="\n") as of:
                of.write(f"{source}\t{url}\t{st}\t{len(body)}\n")
            found.append((source, url, st, out))
    for source, url, st, out in found:
        with open(out, "rb") as evidence:
            data = evidence.read()
        append_finding(target, {
            "asset_kind": "path", "product": "UNSET", "version": "UNSET",
            "version_bound": "UNSET", "provenance": "inferred",
            "evidence_path": os.path.relpath(out, ROOT).replace("\\", "/"),
            "evidence_quote": f"{source}\t{url}\t{st}",
            "asset_sha256": __import__("hashlib").sha256(data).hexdigest(),
            "reasoning": "candidate-paths 관찰물의 GO 승인 후 fetch 결과; 접근 가능성은 이 응답에 한정",
            "verified_by": ["active_recon.py:candidate-paths"],
            "http_status": st,
        })
    odir = os.path.join(ROOT, "targets", target, "captures", "observation")
    with open(os.path.join(odir, f"candidate-probe-{recon_id}.json"), "w", encoding="utf-8") as f:
        json.dump({"recon_id": recon_id, "kind": "candidate-paths", "results": entries}, f, indent=2, ensure_ascii=False)


def main() -> int:
    _utf8_stdio()
    ap = argparse.ArgumentParser(description="Active recon runner (needs human GO)")
    ap.add_argument("ip", help="대상 IP")
    ap.add_argument("--target", required=True, help="host label (targets/<host>/)")
    ap.add_argument("--recon-id", required=True, help="GO 승인된 recon_id")
    ap.add_argument("--approved", action="store_true", help="사람의 GO 승인 확인(없으면 차단)")
    ap.add_argument("--nmap-args", default="-sV --open -p 80,443,22,8080,8000",
                    help="nmap 인자 (기본: 서비스 버전 감지)")
    ap.add_argument("--dir-enum", action="store_true", help="디렉터리 열거 수행")
    ap.add_argument("--dir-wordlist", default=None, help="디렉터리 워드리스트 파일")
    ap.add_argument("--scheme", default="http", choices=["http", "https"])
    ap.add_argument("--port", type=int, default=80, help="디렉터리 열거용 포트")
    ap.add_argument("--host", default=None,
                    help="HTTPS vhost/SNI 용 호스트명 — URL 을 이 호스트로, 스코프 검사는 ip 로")
    ap.add_argument("--server-probe", action="store_true",
                     help="서버사이드 프로브(기본 경로·에러페이지) 수집 후 fingerprint 재실행 (T12)")
    ap.add_argument("--candidate-paths", default=None,
                    help="parse_metafiles.py 관찰물을 GO 승인 후 fetch")
    args = ap.parse_args()

    # ── GO 게이트 ──────────────────────────────────────────────────────────
    if not args.approved:
        print(
            "[STOP] 능동 정찰입니다. 사람의 `GO " + args.recon_id + "` 승인 후 --approved 로 재실행하세요.",
            file=sys.stderr,
        )
        return 3

    # ── 스코프 게이트: 허용 대역 밖이면 요청 전에 STOP ──────────────────────
    if not scope_allows(args.ip):
        print(
            "[STOP] " + args.ip + " 은(는) scope.md 허용 대역 밖입니다. 정찰을 시작하지 않습니다.",
            file=sys.stderr,
        )
        return 3

    rc_sum = 0

    # 1) 포트/서비스 스캔 (nmap)
    nmap = shutil.which("nmap")
    if nmap:
        cmd = [nmap, "-Pn"] + args.nmap_args.split() + [args.ip]
        stdout, stderr, rc, meta = run_and_capture(cmd, "nmap", args.recon_id, args.target)
        rc_sum += rc
        n = banner_findings_from_stdout(stdout, "nmap", args.recon_id, args.target, "nmap")
        print(f"[*] nmap 배너 findings {n}건 반영")
    else:
        print("[!] nmap 없음 — 포트/서비스 스캔 생략(컨테이너 실행 권장: docker/Dockerfile)", file=sys.stderr)
        rc_sum += 1

    # 2) 디렉터리 열거
    if args.dir_enum:
        gobuster = shutil.which("gobuster")
        if gobuster:
            wordlist = args.dir_wordlist or "/usr/share/wordlists/dirb/common.txt"
            if not os.path.exists(wordlist):
                wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
            if not os.path.exists(wordlist):
                print("[!] 워드리스트 없음 — --dir-wordlist 로 지정하세요", file=sys.stderr)
                wordlist = None
            if wordlist:
                base_url = f"{args.scheme}://{args.host or args.ip}:{args.port}/"
                cmd = [gobuster, "dir", "-u", base_url,
                       "-w", wordlist, "-q", "-t", "5"]
                stdout, stderr, rc, meta = run_and_capture(cmd, "dir", args.recon_id, args.target)
                rc_sum += rc
                n = banner_findings_from_stdout(stdout, "dir", args.recon_id, args.target, "dir")
                print(f"[*] 디렉터리 findings {n}건 반영")
        else:
            words = []
            wpath = args.dir_wordlist
            if wpath and os.path.exists(wpath):
                with open(wpath, encoding="utf-8", errors="replace") as f:
                    words = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
            if not words:
                words = DEFAULT_DIRS
            stdout = dir_enum_fallback(args.ip, args.port, args.scheme, args.target, args.recon_id, words)
            rc = 0
            run_and_capture  # noqa: B018  (stdout 은 아래 저장 경로로 직접 기록)
            odir = os.path.join(ROOT, "targets", args.target, "captures", "observation")
            txt_path = os.path.join(odir, f"dir-{args.recon_id}.txt")
            with open(txt_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(stdout)
            meta = {"recon_id": args.recon_id, "command": ["python-dir-enum-fallback"], "exit_code": 0}
            print(f"[*] python 폴백 dir enum -> {os.path.relpath(txt_path, ROOT)}")
            n = banner_findings_from_stdout(stdout, "dir", args.recon_id, args.target, "dir")
            print(f"[*] 디렉터리 findings {n}건 반영")
            rc_sum += rc

    # 3) 서버사이드 프로브 (T12) — 기본 경로·에러 유발 지문
    if args.server_probe:
        server_probe(args.target, args.ip, args.port, args.scheme, args.recon_id, host=args.host)

    if args.candidate_paths:
        if not os.path.exists(args.candidate_paths):
            print(f"[!] candidate file not found: {args.candidate_paths}", file=sys.stderr)
            return 2
        candidate_probe(args.target, args.ip, args.port, args.scheme, args.recon_id,
                        args.candidate_paths, host=args.host)

    print(f"\n[*] 완료. 재검증/확정 후 게이트: npm run check -- {args.target}")
    return 0 if rc_sum == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
