#!/usr/bin/env python3
"""AWS 인프라 정찰 (T14) — S3 버킷 공개 여부 + 메타데이터 접근 신호 기록.

힌트("AWS 인프라 사용")에 대응하는 별도 표면이다. 웹 자산 정찰만으로는 S3/메타데이터 계층을
못 본다. 전부 스코프·GO 규율을 따른다.

- S3 버킷 공개 여부: 베이스 도메인/회사명에서 버킷 이름 후보를 생성하고
  https://<bucket>.s3.amazonaws.com/?list-type=2 로 공개 리스팅을 확인한다.
  ⚠️ 공인 AWS 엔드포인트(s3.amazonaws.com) 접근은 scope.md 예외 처리다 — CTF 가 허용한 범위
  안에서만, 그리고 `--approved-for-public`(사람 확인) 없이는 실행하지 않는다.
- 메타데이터(169.254.169.254): 실제 취득은 익스플로잇 하네스 영역이다. 정찰 하네스는
  "메타데이터 접근 가능성 신호"(SSRF 류 엔드포인트 존재 등)만 기록하고 취득은 위임한다.

Usage:
    python scripts/aws_recon.py corp  --target 10.10.110.5 --s3-buckets --approved-for-public
    python scripts/aws_recon.py corp  --target 10.10.110.5 --signal-only
"""
import argparse
import hashlib
import json
import os
import re
import sys
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import sys as _sys
_sys.path.insert(0, os.path.join(ROOT, "scripts"))
from lib.engagement import stamp_findings  # noqa: E402


def _utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def bucket_candidates(base):
    base = base.lower().strip()
    words = re.sub(r"[^a-z0-9]", "-", base)
    return sorted(set(filter(None, [
        words,
        words + "-assets", words + "-static", words + "-uploads",
        words + "-backup", words + "-backups", words + "-logs",
        words + "-media", words + "-prod", words + "-staging",
        "assets-" + words, "static-" + words, "backup-" + words,
    ])))


def check_public_bucket(bucket):
    """공개 리스팅 여부 확인. (status, is_public, snippet) 반환. 접근 실패는 실패로 보존."""
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError
    url = f"https://{bucket}.s3.amazonaws.com/?list-type=2"
    req = Request(url, headers={"User-Agent": "recon-harness/0.1"})
    try:
        resp = urlopen(req, timeout=15)
        body = resp.read(200000).decode("utf-8", "replace")
        public = resp.status == 200 and ("<ListBucketResult" in body or "<Contents>" in body)
        return resp.status, public, body[:400]
    except HTTPError as e:
        return e.code, False, ""
    except URLError as e:
        return None, False, f"URLError: {e.reason}"
    except Exception as e:  # noqa: BLE001
        return None, False, f"{type(e).__name__}: {e}"


def add_finding(host, findings, existing, fid, payload):
    key = (payload.get("evidence_path"), payload.get("evidence_quote"))
    if key in existing:
        return fid
    existing.add(key)
    fid += 1
    payload["finding_id"] = f"FND-{fid:03d}"
    payload["report_eligible"] = False
    findings.append(payload)
    return fid


def main() -> int:
    _utf8_stdio()
    ap = argparse.ArgumentParser(description="AWS infra recon (S3 public check / metadata signal)")
    ap.add_argument("base", help="회사/도메인 이름 (S3 버킷 이름 후보 생성용)")
    ap.add_argument("--target", required=True, help="host label (targets/<host>/)")
    ap.add_argument("--s3-buckets", action="store_true", help="S3 버킷 공개 여부 확인(공인 AWS 접근)")
    ap.add_argument("--approved-for-public", action="store_true",
                    help="공인 AWS 엔드포인트 접근을 사람이 허용함(없으면 차단)")
    ap.add_argument("--signal-only", action="store_true",
                    help="메타데이터 접근 신호(SSRF 류)만 기록 — 네트워크 요청 없음")
    args = ap.parse_args()

    fpath = os.path.join(ROOT, "targets", args.target, "findings.json")
    doc = {"findings": []}
    if os.path.exists(fpath):
        with open(fpath, encoding="utf-8") as f:
            doc = json.load(f)
    findings = doc.get("findings", [])
    existing = {(f.get("evidence_path"), f.get("evidence_quote")) for f in findings}
    fid = max([int(x["finding_id"].split("-")[-1]) for x in findings] or [0])

    odir = os.path.join(ROOT, "targets", args.target, "captures", "observation")
    os.makedirs(odir, exist_ok=True)

    if args.signal_only:
        # 메타데이터 접근 신호: 수집 자산/엔드포인트에서 SSRF 류 대상(내부/메타) 흔적만 기록
        obs = {"kind": "aws-metadata-signal", "note": "신호 기록만. 실제 취득은 익스플로잇 하네스 영역."}
        for f in findings:
            ep = f.get("endpoint") or ""
            if ep and re.search(r"(?i)(local|internal|127\.0\.0\.1|169\.254|0\.0\.0\.0|metadata)", ep):
                obs.setdefault("signals", []).append(ep)
        opath = os.path.join(odir, "aws-metadata-signal.json")
        with open(opath, "w", encoding="utf-8") as fo:
            json.dump(obs, fo, indent=2, ensure_ascii=False)
        print(f"[*] 메타데이터 접근 신호 {len(obs.get('signals', []))}건 -> "
              f"{os.path.relpath(opath, ROOT)}")
        return 0

    if args.s3_buckets:
        if not args.approved_for_public:
            print("[STOP] 공인 AWS 엔드포인트 접근은 scope 예외 처리다. 사람의 허용 후 "
                  "--approved-for-public 로 재실행하세요.", file=sys.stderr)
            return 3
        lines = []
        results = []
        for bucket in bucket_candidates(args.base):
            st, public, snippet = check_public_bucket(bucket)
            results.append({"bucket": bucket, "status": st, "public_listing": public})
            lines.append(f"{bucket} status={st} public_listing={public}"
                         + (f" snippet={snippet[:120]}" if public else ""))
            print(f"[{'OPEN' if public else '--'}] {bucket} status={st} public_listing={public}")
        obs_txt = "\n".join(lines) + "\n"
        obs_path = os.path.join(odir, "aws-s3-check.json")
        with open(obs_path, "w", encoding="utf-8") as fo:
            json.dump({"kind": "aws-s3", "results": results, "finished_at": now_iso()},
                      fo, indent=2, ensure_ascii=False)
        data = obs_txt.encode("utf-8")
        sha = hashlib.sha256(data).hexdigest()
        for r in results:
            if not r["public_listing"]:
                continue
            quote = f"{r['bucket']} status={r['status']} public_listing=True"
            fid = add_finding(args.target, findings, existing, fid, {
                "asset_kind": "aws-s3",
                "product": "aws:s3-public-bucket",
                "version": r["bucket"],
                "version_bound": "UNSET",
                "provenance": "confirmed",
                "evidence_path": os.path.relpath(obs_path, ROOT).replace("\\", "/"),
                "evidence_quote": quote,
                "asset_sha256": sha,
                "reasoning": "aws_recon: S3 버킷 공개 리스팅 확인 — 도구 응답 실재(confirmed). "
                             "CTF 허용 범위 내 공인 접근",
                "verified_by": ["aws_recon.py:s3-public"],
            })
        print(f"[*] S3 후보 {len(results)}건, 공개 {sum(1 for r in results if r['public_listing'])}건")
        print(f"[*] Observation: {os.path.relpath(obs_path, ROOT)}")

    stamp_findings(findings, "aws_recon.py")
    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    print("[*] 게이트 확인: npm run check -- " + args.target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
