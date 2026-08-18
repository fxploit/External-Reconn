#!/usr/bin/env python3
"""자산 기반 추출 패스 — 시크릿·엔드포인트·에러/스택트레이스·주석·내부IP (T15, WSTG-INFO-05).

이미 수집·정규화한 자산(js/css/html)에서 결정론적 regex 로 고가치 문자열을 뽑는다.
cariddi 가 하는 일의 파이썬 폴백이자 독립 도구. 컨테이너에 cariddi 바이너리가 있으면
--cariddi 로 그 JSON 출력을 찾아 병합할 수도 있다.

환각 통제(증거 바인딩 + 등급 분리):
 - 매치 문자열의 '존재 자체'는 confirmed (evidence_path=자산, evidence_quote=실재 부분 문자열).
   단, 시크릿은 원문을 findings 에 두지 않는다 — evidence_quote 는 형식 프리픽스(AKIA 등, 비밀 아님),
   원문은 gitignore 대상 observation 파일에 보존. `secret_masked`=앞4자+길이.
 - '진짜 유효한 시크릿/실사용 엔드포인트인가'는 inferred — reasoning 에 명시(regex 오탐 가능).
 - 에러페이지의 버전 문자열은 confirmed(원문 실재). 그 버전이 제품 버전이라는 해석은 별도(시그니처 규율).

Usage:
    python scripts/extract_assets.py <host> [--cariddi]
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KINDS = ("js", "css", "html", "metafile")
from lib.engagement import append_event, stamp_findings  # noqa: E402

# WSTG-INFO-05: 클라이언트 리소스에 남은 개발자 주석(레거시 엔드포인트·TODO·내부 정보 단서).
# 존재는 confirmed, '민감한 누출인가'의 해석은 사람 몫(inferred).
COMMENT_RULES = [
    {"id": "html-comment", "kinds": ("html", "metafile"), "regex": re.compile(r"<!--(.*?)-->", re.S)},
    {"id": "block-comment", "kinds": ("js", "css"), "regex": re.compile(r"/\*(.*?)\*/", re.S)},
]
# 사설/루프백 IPv4 (RFC1918 + 127/8). 존재는 confirmed, '내부 인프라 주소인가'는 inferred(오탐 가능).
PRIVATE_IP = re.compile(
    r"(?<![\w.])("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r")(?![\w.])"
)
IP_NOISE = {"0.0.0.0", "127.0.0.1", "192.168.0.1", "192.168.1.1"}
COMMENT_TAG_RULES = (
    ("TODO", re.compile(r"\bTODO\b", re.I)),
    ("FIXME", re.compile(r"\bFIXME\b", re.I)),
    ("XXX", re.compile(r"\bXXX\b", re.I)),
    ("HACK", re.compile(r"\bHACK\b", re.I)),
    ("internal-host", re.compile(r"(?:\.local\b|\.htb\b|(?:10|127)\.\d|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)", re.I)),
    ("credential-ish", re.compile(r"\b(?:password|passwd|api[_-]?key|token|secret)\b", re.I)),
    ("legacy-endpoint", re.compile(r"(?:/api(?:/|\b)|\.php\b|commented[- ]?out)", re.I)),
)
# 주석 잡음 억제: 콘텐츠(양끝 공백 제거)가 이 길이 미만이면 스킵, 자산당 상한.
COMMENT_MIN_CHARS = 6
COMMENT_MAX_PER_ASSET = 40


def is_private_ipv4(s: str) -> bool:
    """옥텟 범위(0~255) + RFC1918/루프백 소속을 확정 검증 — 버전 문자열 등 오탐 축소.
    PRIVATE_IP 정규식과 이중 검증(정규식이 느슨해도 여기서 최종 확정)."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        o = [int(p) for p in parts]
    except ValueError:
        return False
    if not all(0 <= p <= 255 for p in o):
        return False
    return (
        o[0] == 10
        or (o[0] == 192 and o[1] == 168)
        or (o[0] == 172 and 16 <= o[1] <= 31)
        or o[0] == 127
    )


def byte_quote(candidate: str, data: bytes, maxlen: int = 160):
    """evidence_quote 는 원본 자산 바이트에 실재해야 한다(게이트 재검증과 동일 규율).
    후보 접두사의 UTF-8 바이트가 파일에 있으면 그대로, 없으면(cp949 등 인코딩 불일치)
    자산 바이트에 실재하는 ASCII 런으로 대체한다. 못 찾으면 None(바인딩 불가 → 스킵)."""
    q = candidate[:maxlen].strip()
    if q and q.encode("utf-8") in data:
        return q
    for run in re.findall(r"[\x20-\x7e]{6,}", candidate):
        rq = run[:maxlen].strip()
        if rq and rq.encode("utf-8") in data:
            return rq
    return None


def comment_tags(content: str):
    return [name for name, rule in COMMENT_TAG_RULES if rule.search(content)]


def ip_context(text: str, start: int, end: int, asset_kind: str, ip: str):
    context = text[max(0, start - 32):min(len(text), end + 32)]
    semver_adjacent = bool(re.search(r"(?<![\d.])\d+\.\d+\.\d+(?![\d.])", context))
    vendor_asset = asset_kind in ("js", "css") and bool(re.search(r"(?:react|vue|angular|vendor|webpack|jquery)", context, re.I))
    noise = ip in IP_NOISE
    if semver_adjacent or vendor_asset:
        confidence = "guess"
    else:
        confidence = "inferred"
    return confidence, noise


def masked_comment_quote(content: str, data: bytes):
    """Return a byte-bound safe excerpt; never put a detected secret in findings."""
    safe = content
    for rule in SECRET_RULES:
        safe = rule["regex"].sub(lambda m: m.group(0)[:4] + "...", safe)
    # A masked string is not present in the raw asset, so bind an excerpt that
    # ends before the first secret. The full masked value remains metadata only.
    first_secret = min((m.start() for r in SECRET_RULES for m in r["regex"].finditer(content)), default=len(content))
    prefix = content[:first_secret].strip() or "comment"
    return byte_quote(prefix, data) or byte_quote("comment", data)

SECRET_RULES = [
    {"id": "aws-access-key", "prefix": "AKIA",
     "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b")},
    {"id": "aws-access-key-asia", "prefix": "ASIA",
     "regex": re.compile(r"\bASIA[0-9A-Z]{16}\b")},
    {"id": "github-token", "prefix": "ghp_",
     "regex": re.compile(r"\bghp_[A-Za-z0-9]{36}\b")},
    {"id": "google-api-key", "prefix": "AIza",
     "regex": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")},
    {"id": "slack-token", "prefix": "xox",
     "regex": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")},
    {"id": "private-key", "prefix": "-----BEGIN",
     "regex": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")},
    {"id": "aws-secret-key", "prefix": "aws_secret",
     "regex": re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key)['\"]?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})")},
]
ENDPOINT_RULES = [
    {"id": "http-url", "regex": re.compile(r"https?://[^\s\"'<>]+")},
    {"id": "api-path",
     "regex": re.compile(r"(?<![A-Za-z0-9])(/(?:api|v[0-9]+|rest|graphql)[A-Za-z0-9_/\-\.]*)")},
]
ERROR_RULES = [
    {"id": "python-traceback", "prefix": "Traceback",
     "regex": re.compile(r"Traceback \(most recent call last\)")},
    {"id": "framework-version",
     "regex": re.compile(r"(?i)\b(?:django|flask|werkzeug|spring|tomcat|apache|nginx|php|rails)\s*/?\s*"
                         r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b")},
]


def _utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mask(secret: str) -> str:
    return f"{secret[:4]}...len={len(secret)}"


def decode_bytes(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "cp949"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1")


def load_doc(host):
    fpath = os.path.join(ROOT, "targets", host, "findings.json")
    with open(fpath, encoding="utf-8") as f:
        return json.load(f)


def run_cariddi(target, manifest, findings, existing):
    """컨테이너의 cariddi 를 진입 URL 에 돌려 JSON 출력을 observation 에 보존하고,
    수집 자산에 실재하는 매치만 finding 으로 바인딩한다(존재 confirmed).

    cariddi 는 크롤러라 네트워크 요청을 보낸다(depth 0 = 진입 URL 1건). --cariddi 가 명시될 때만.
    파싱은 cariddi v1.4.6 JSON 스키마를 견고하게 처리한다(문자열 필드를 전부 후보로).
    """
    entry_url = manifest.get("entry_url")
    if not entry_url:
        print("[!] --cariddi: manifest 에 entry_url 이 없어 실행 불가", file=sys.stderr)
        return 0
    binary = shutil.which("cariddi")
    if not binary:
        print("[!] --cariddi: cariddi 바이너리 없음(컨테이너 실행 권장: docker/Dockerfile)", file=sys.stderr)
        return 0

    print(f"[*] cariddi 실행(진입 URL, depth 0): {entry_url}")
    try:
        proc = subprocess.run([binary, "-s", "-e", "-err", "-json", "-md", "0", "-t", "10"],
                              input=(entry_url + "\n"), capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        print("[!] cariddi 실행 실패", file=sys.stderr)
        return 0

    odir = os.path.join(ROOT, "targets", target, "captures", "observation")
    raw = proc.stdout
    obs_path = os.path.join(odir, f"extract-{target}-cariddi.json")
    with open(obs_path, "w", encoding="utf-8") as f:
        f.write(raw or "(stdout empty)\nstderr:\n" + proc.stderr[-2000:])
    print(f"[*] cariddi 원본 JSON: {os.path.relpath(obs_path, ROOT)} (exit={proc.returncode})")

    # 수집 자산 텍스트 캐시 — 매치가 실재하는 자산에만 바인딩
    assets_text = []
    for a in manifest.get("assets", []):
        ref = a.get("raw_ref")
        if not ref or os.path.exists(os.path.join(ROOT, ref)) is False:
            continue
        try:
            data = open(os.path.join(ROOT, ref), "rb").read()
        except OSError:
            continue
        assets_text.append((a, decode_bytes(data), data))

    def bind(full):
        for a, text, data in assets_text:
            if full.encode("utf-8") in data:
                return a, data
        return None, None

    added = 0
    items = []
    for line in raw.splitlines():  # cariddi 는 NDJSON(라인별 객체) 출력
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if not items:
        print("[!] cariddi JSON 항목 없음 — 원본은 observation 에 보존됨", file=sys.stderr)
        return 0
    for item in items:
        if not isinstance(item, dict):
            continue
        url = item.get("url", "")
        matches = item.get("matches") or {}
        for field in ("secrets", "endpoints", "errors", "interestingFiles", "interestingSubdomains"):
            for val in matches.get(field, []) or []:
                # cariddi 항목은 문자열 또는 {"name":..., "match":...} 객체일 수 있다
                if isinstance(val, dict):
                    full = val.get("match") or val.get("url") or val.get("name") or ""
                else:
                    full = val
                full = str(full).strip()
                if not full:
                    continue
                a, data = bind(full)
                if a is None:
                    continue
                key = (a.get("raw_ref"), full[:120])
                if key in existing:
                    continue
                existing.add(key)
                fid = max([int(x["finding_id"].split("-")[-1]) for x in findings] or [0]) + 1
                # 시크릿은 원문을 findings 에 두지 않는다 — 형식 프리픽스만 인용, 원문은 observation
                if field == "secrets":
                    quote = next((r["prefix"] for r in SECRET_RULES if r["regex"].search(full)), full[:4])
                    extra = {"secret_masked": mask(full)}
                else:
                    quote, extra = full[:120], {}
                findings.append({
                    "finding_id": f"FND-{fid:03d}",
                    "asset_kind": a.get("asset_kind", "other"),
                    "product": "cariddi:" + field,
                    "version": "unknown",
                    "version_bound": "UNSET",
                    "provenance": "confirmed",
                    "evidence_path": a.get("raw_ref"),
                    "evidence_quote": quote,
                    "asset_sha256": a.get("asset_sha256"),
                    "reasoning": f"cariddi({field}) 매치가 수집 자산에 실재(confirmed) — 유효성/실사용은 미확인. 원본: {url}",
                    "verified_by": ["extract_assets.py:cariddi:" + field],
                    **extra,
                })
                added += 1
    return added


def main() -> int:
    _utf8_stdio()
    ap = argparse.ArgumentParser(description="Asset extraction: secrets/endpoints/error-version")
    ap.add_argument("target", help="host label (targets/<host>/)")
    ap.add_argument("--cariddi", action="store_true", help="컨테이너의 cariddi 가 있으면 사용")
    args = ap.parse_args()
    target_ip = args.target if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", args.target) else ""

    fpath = os.path.join(ROOT, "targets", args.target, "findings.json")
    if not os.path.exists(fpath):
        print(f"[!] findings.json not found: {fpath} — run fingerprint.py first", file=sys.stderr)
        return 2
    doc = load_doc(args.target)
    manifest_path = os.path.join(ROOT, "targets", args.target, "captures", "manifest.json")
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)

    odir = os.path.join(ROOT, "targets", args.target, "captures", "observation")
    os.makedirs(odir, exist_ok=True)
    obs_path = os.path.join(odir, f"extract-{args.target}.json")

    findings = doc.get("findings", [])
    existing = {(f.get("evidence_path"), f.get("evidence_quote")) for f in findings}
    obs = {"secrets": [], "endpoints": [], "errors": [],
           "comments": [], "internal_ips": [], "assets_scanned": 0}

    def add(finding, obs_kind, obs_entry):
        key = (finding["evidence_path"], finding["evidence_quote"])
        if key in existing:
            return
        existing.add(key)
        fid = max([int(x["finding_id"].split("-")[-1]) for x in findings] or [0]) + 1
        finding["finding_id"] = f"FND-{fid:03d}"
        finding["report_eligible"] = False
        findings.append(finding)
        obs[obs_kind].append(obs_entry)

    for asset in manifest.get("assets", []):
        kind = asset.get("asset_kind")
        raw_ref = asset.get("raw_ref")
        if kind not in KINDS or not raw_ref:
            continue
        raw_path = os.path.join(ROOT, raw_ref)
        if not os.path.exists(raw_path):
            continue
        with open(raw_path, "rb") as f:
            data = f.read()
        text = decode_bytes(data)
        obs["assets_scanned"] += 1
        sha = asset.get("asset_sha256") or sha256_hex(data)

        # ── 시크릿 (존재 confirmed, 원문은 observation/gitignore 에만) ──────
        for rule in SECRET_RULES:
            for m in rule["regex"].finditer(text):
                full = m.group(0)
                if rule["id"] == "aws-secret-key":
                    full = m.group(1)
                obs_entry = {"rule": rule["id"], "asset": raw_ref, "secret": full}
                add({
                    "asset_kind": "secret",
                    "product": "secret:" + rule["id"],
                    "version": "unknown",
                    "version_bound": "UNSET",
                    "provenance": "confirmed",
                    "evidence_path": raw_ref,
                    "evidence_quote": rule["prefix"],
                    "asset_sha256": sha,
                    "reasoning": (f"extract_assets: {rule['id']} 형식 문자열 존재(confirmed) — "
                                  f"유효성/실사용은 미확인(inferred 해석). 원문은 "
                                  f"observation/extract-{args.target}.json"),
                    "verified_by": ["extract_assets.py:" + rule["id"]],
                    "secret_masked": mask(full),
                }, "secrets", obs_entry)

        # ── 엔드포인트 (존재는 확실, 실사용은 inferred) ─────────────────────
        for rule in ENDPOINT_RULES:
            for m in rule["regex"].finditer(text):
                ep = m.group(1) if rule["id"] == "api-path" and m.lastindex else m.group(0)
                if len(ep) > 200:
                    ep = ep[:200]
                obs_entry = {"rule": rule["id"], "asset": raw_ref, "endpoint": ep}
                add({
                    "asset_kind": "endpoint",
                    "product": "endpoint:" + rule["id"],
                    "version": "unknown",
                    "version_bound": "UNSET",
                    "provenance": "inferred",
                    "evidence_path": raw_ref,
                    "evidence_quote": ep,
                    "asset_sha256": sha,
                    "reasoning": f"extract_assets: {rule['id']} 발견 — 실사용 여부는 미확인(inferred)",
                    "verified_by": ["extract_assets.py:" + rule["id"]],
                    "endpoint": ep,
                }, "endpoints", obs_entry)

        # ── WSTG-INFO-05: 개발자 주석 (존재 confirmed, 누출 해석은 inferred/사람) ──
        for rule in COMMENT_RULES:
            if kind not in rule["kinds"]:
                continue
            hits = 0
            for m in rule["regex"].finditer(text):
                content = (m.group(1) or "").strip()
                if len(content) < COMMENT_MIN_CHARS:
                    continue
                quote = masked_comment_quote(content, data)
                if quote is None:
                    continue  # 자산 바이트에 실재 근거를 못 만들면 스킵(환각 방지)
                hits += 1
                if hits > COMMENT_MAX_PER_ASSET:
                    break
                tags = comment_tags(content)
                obs_entry = {"rule": rule["id"], "asset": raw_ref, "comment": content[:400], "comment_tags": tags}
                add({
                    "asset_kind": "comment",
                    "product": "comment:" + rule["id"],
                    "version": "unknown",
                    "version_bound": "UNSET",
                    "provenance": "confirmed",
                    "evidence_path": raw_ref,
                    "evidence_quote": quote,
                    "evidence_quote_masked": re.sub(r"\S*(?:password|token|secret|api[_-]?key)\S*", "[REDACTED]", content, flags=re.I)[:160],
                    "asset_sha256": sha,
                    "reasoning": (f"extract_assets: {rule['id']} 주석이 자산에 실재(confirmed) — "
                                  f"민감정보 누출 여부는 사람 검토(inferred)"),
                    "verified_by": ["extract_assets.py:" + rule["id"]],
                    "comment_tags": tags,
                    "report_eligible": False,
                }, "comments", obs_entry)

        # ── WSTG-INFO-05: 내부/사설 IP 노출 (존재 confirmed, 내부 인프라 해석은 inferred) ──
        seen_ips = set()
        for m in PRIVATE_IP.finditer(text):
            ip = m.group(1)
            if ip in seen_ips or not is_private_ipv4(ip):
                continue
            quote = byte_quote(ip, data)
            if quote is None:
                continue
            seen_ips.add(ip)
            confidence, ip_noise = ip_context(text, m.start(), m.end(), kind, ip)
            self_ref = bool(target_ip and target_ip == ip)
            obs_entry = {"asset": raw_ref, "ip": ip, "confidence": confidence,
                         "ip_noise": ip_noise, "self_reference": self_ref}
            add({
                "asset_kind": "internal-ip",
                "product": "internal-ip",
                "version": "unknown",
                "version_bound": "UNSET",
                "provenance": "confirmed",
                "evidence_path": raw_ref,
                "evidence_quote": quote,
                "asset_sha256": sha,
                "reasoning": (f"extract_assets: 사설/루프백 IP '{ip}' 문자열이 자산에 실재(confirmed) — "
                               f"내부 인프라 가능성 confidence={confidence}; 문맥 기반이며 존재 자체와 분리"),
                "verified_by": ["extract_assets.py:internal-ip"],
                "confidence": confidence,
                "ip_noise": ip_noise,
                "self_reference": self_ref,
                "report_eligible": False,
            }, "internal_ips", obs_entry)

        # security.txt 연락처는 공개 목적이어도 report/findings에는 마스킹한다.
        if kind == "metafile" and re.search(r"(?:^|\n)\s*Contact\s*:", text, re.I):
            for cm in re.finditer(r"(?im)^\s*Contact\s*:\s*<?([^\s>]+@[^\s>]+)>?", text):
                email = cm.group(1)
                local, domain = email.split("@", 1)
                masked = (local[:1] + "***@" + domain) if local else "***@" + domain
                q = byte_quote("Contact:", data)
                if q:
                    add({
                        "asset_kind": "contact",
                        "product": "security.txt-contact",
                        "version": "unknown",
                        "version_bound": "UNSET",
                        "provenance": "confirmed",
                        "evidence_path": raw_ref,
                        "evidence_quote": q,
                        "asset_sha256": sha,
                        "reasoning": "security.txt Contact 필드 존재; PII는 마스킹하여 보고",
                        "verified_by": ["extract_assets.py:security-contact"],
                        "contact_masked": masked,
                        "report_eligible": False,
                    }, "comments", {"rule": "security-contact", "asset": raw_ref, "contact_masked": masked})

        # ── 에러/스택트레이스·버전 문자열 (존재 confirmed) ───────────────────
        for rule in ERROR_RULES:
            for m in rule["regex"].finditer(text):
                full = m.group(0)
                ver = m.group(1) if rule["id"] == "framework-version" and m.lastindex else None
                obs_entry = {"rule": rule["id"], "asset": raw_ref, "match": full}
                if rule["id"] == "framework-version" and ver:
                    obs_entry["version"] = ver
                add({
                    "asset_kind": "error",
                    "product": "error:" + rule["id"],
                    "version": ver or "unknown",
                    "version_bound": "UNSET",
                    "provenance": "confirmed",
                    "evidence_path": raw_ref,
                    "evidence_quote": full[:120],
                    "asset_sha256": sha,
                    "reasoning": (f"extract_assets: {rule['id']} 발견 — 에러페이지/스택에 실재(confirmed). "
                                  f"버전 해석은 제품 시그니처 규율을 따름"),
                    "verified_by": ["extract_assets.py:" + rule["id"]],
                }, "errors", obs_entry)

    with open(obs_path, "w", encoding="utf-8") as f:
        json.dump(obs, f, indent=2, ensure_ascii=False)

    stamp_findings(findings, "extract_assets.py")
    doc["findings"] = findings
    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)

    n_cariddi = 0
    if args.cariddi:
        n_cariddi = run_cariddi(args.target, manifest, findings, existing)
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)
    append_event(args.target, {
        "event": "extract_assets",
        "produced_by": "extract_assets.py",
        "findings_ref": f"targets/{args.target}/findings.json",
    })

    print(f"[*] 자산 스캔 {obs['assets_scanned']}건 / 시크릿 {len(obs['secrets'])} · "
          f"엔드포인트 {len(obs['endpoints'])} · 에러 {len(obs['errors'])} · "
          f"주석 {len(obs['comments'])} · 내부IP {len(obs['internal_ips'])}"
          + (f" · cariddi {n_cariddi}" if args.cariddi else ""))
    print(f"[*] 시크릿 원문(gitignore): {os.path.relpath(obs_path, ROOT)}")
    print("[*] 게이트 확인: npm run check -- " + args.target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
