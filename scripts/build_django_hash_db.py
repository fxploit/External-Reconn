#!/usr/bin/env python3
"""Django admin 정적 자산 해시 DB 구축 도구 (T11).

Django 의 관리자 정적 파일(admin/css/base.css 등)은 버전별로 거의 변하지 않아
자산 해시 → Django 버전 판별의 결정론적 근거가 된다. 이 도구는 **Django 공식 PyPI 릴리스
휠에서** 정적 자산을 추출해 sha256 을 계산한다(추측 금지 — 실재 산출물 기준).

사용:
    python scripts/build_django_hash_db.py --versions 3.2.25,4.2.11,5.0.6,5.1.6
        -> harness/signatures/maps/django-static-hashes.json

출처: https://pypi.org/project/Django/ (공식 릴리스 휠). license: BSD-3-Clause.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET_ASSETS = [
    "admin/css/base.css",
    "admin/css/login.css",
    "admin/css/nav_sidebar.css",
]


def _utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_hashes(wheel_path):
    """휠 안의 admin 정적 자산 sha256 -> {asset, sha256} 목록."""
    out = {}
    with zipfile.ZipFile(wheel_path) as z:
        for name in z.namelist():
            # django/contrib/admin/static/admin/css/base.css 형태
            for asset in TARGET_ASSETS:
                if name.endswith("/static/" + asset):
                    data = z.read(name)
                    out.setdefault(sha256_hex(data), {"asset": asset, "sha256": sha256_hex(data)})
    return out


def main() -> int:
    _utf8_stdio()
    ap = argparse.ArgumentParser(description="Build Django admin static asset hash DB (from official PyPI wheels)")
    ap.add_argument("--versions", required=True, help="콤마로 구분한 Django 버전 목록")
    ap.add_argument("--output", default=os.path.join(ROOT, "harness", "signatures", "maps", "django-static-hashes.json"))
    args = ap.parse_args()

    versions = [v.strip() for v in args.versions.split(",") if v.strip()]
    if not versions:
        print("[!] --versions 필요", file=sys.stderr)
        return 2

    db = {"source": "Django 공식 PyPI 릴리스 휠에서 admin 정적 자산 추출 (license: BSD-3-Clause).",
          "built_by": "scripts/build_django_hash_db.py", "hashes": {}}

    with tempfile.TemporaryDirectory() as tmp:
        for ver in versions:
            print(f"[*] download Django {ver} ...")
            r = subprocess.run([sys.executable, "-m", "pip", "download", f"Django=={ver}",
                                "--no-deps", "-d", tmp], capture_output=True, text=True)
            if r.returncode != 0:
                print(f"[!] download 실패 {ver}: {r.stderr[-500:]}", file=sys.stderr)
                continue
            wheels = [f for f in os.listdir(tmp) if f.endswith(".whl")]
            if not wheels:
                print(f"[!] wheel 없음 {ver}", file=sys.stderr)
                continue
            hits = extract_hashes(os.path.join(tmp, wheels[0]))
            if not hits:
                print(f"[!] admin 정적 자산 없음 {ver}", file=sys.stderr)
                continue
            for sha, rec in hits.items():
                entry = db["hashes"].setdefault(sha, {"asset": rec["asset"], "versions": []})
                if ver not in entry["versions"]:
                    entry["versions"].append(ver)
            os.remove(os.path.join(tmp, wheels[0]))
            print(f"[+] {ver}: {len(hits)} 자산 해시")

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)
    n = len(db["hashes"])
    print(f"\n[*] hash DB {n}건 -> {os.path.relpath(args.output, ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
