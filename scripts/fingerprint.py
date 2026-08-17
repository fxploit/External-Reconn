#!/usr/bin/env python3
"""결정론적 핑거프린터.

harness/signatures/*.json 규칙을 수집 자산(정규화본 우선, 없으면 원본)에 매칭한다.
매칭 결과를 targets/<host>/findings.json 으로 쓴다(harness/templates/finding.json 스키마).

환각 통제 원칙(invariants.md):
 - evidence_quote 는 매칭된 '실제 파일 부분 문자열'을 그대로 담는다(재검증 가능).
 - asset_sha256 은 manifest 값을 그대로 옮긴다(파일에서 재계산 검증 가능).
 - 정확 버전을 캡처하면 provenance=confirmed, 범위만이면 시그니처의 implies.provenance 사용.
 - 매칭 안 된 자산은 unmatched 로 보존한다(삭제 금지). AI fallback 추론의 입력이 된다.

Usage:
    python scripts/fingerprint.py <host>
"""
import argparse
import glob
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIG_DIR = os.path.join(ROOT, "harness", "signatures")


def load_signatures():
    sigs = []
    for path in sorted(glob.glob(os.path.join(SIG_DIR, "*.json"))):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        product = data.get("product", "UNKNOWN")
        for s in data.get("signatures", []):
            s["_product"] = product
            sigs.append(s)
    return sigs


def decode_bytes(data: bytes) -> str:
    """한글 등 인코딩을 견고하게 디코딩한다.

    UTF-8(BOM 포함) → CP949(EUC-KR) → latin-1 순으로 시도한다. latin-1은 모든 바이트를
    무손실 매핑하므로 최종 폴백으로 항상 성공한다(매칭용 텍스트 확보). 단, 근거 바인딩은
    항상 '실제 파일 바이트'로 재검증하므로(bind_evidence 참고) 디코딩 방식과 무관하게
    게이트와 일치한다.
    """
    for enc in ("utf-8-sig", "utf-8", "cp949"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1")


def _read(ref):
    if not ref:
        return None
    path = os.path.join(ROOT, ref)
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        data = f.read()
    return ref.replace("\\", "/"), decode_bytes(data), data


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_for(asset):
    """매칭용 텍스트(정규화본 우선)와 근거 바인딩 후보(raw, normalized)를 함께 반환.

    반환: (match_ref, match_text, raw_triple, norm_triple)  또는 None
      raw_triple/norm_triple = (ref, text, bytes) 또는 None
    매칭은 언패킹 이득을 위해 정규화본 텍스트에서 하되, 근거(evidence)는
    'quote의 UTF-8 바이트가 실제로 들어있는 파일 바이트'에 바인딩한다(원본 우선).
    이래야 게이트가 파일을 어떤 인코딩으로 열든(바이트 검색) 재검증이 일치한다.
    """
    raw_triple = _read(asset.get("raw_ref"))
    norm_triple = _read(asset.get("normalized_ref"))
    match_triple = norm_triple or raw_triple
    if match_triple is None:
        return None
    return match_triple[0], match_triple[1], raw_triple, norm_triple


def bind_evidence(quote: str, raw_triple, norm_triple):
    """quote의 UTF-8 바이트가 실재하는 파일에 근거를 바인딩한다(원본 우선).

    반환: (evidence_ref, asset_sha256) 또는 None(어느 파일에도 바이트로 존재하지 않으면).
    게이트도 동일하게 Buffer.from(quote,'utf8') 바이트를 파일 바이트에서 찾으므로
    파일 자체 인코딩(CP949/UTF-8/BOM 등)과 무관하게 항상 일치한다.
    """
    needle = quote.encode("utf-8")
    for triple in (raw_triple, norm_triple):
        if triple is None:
            continue
        ref, _text, data = triple
        if needle in data:
            return ref, _sha256_bytes(data)
    return None


def match_signature(sig, text):
    m = sig.get("match", {})
    pattern = m.get("pattern", "")
    if not pattern:
        return None
    if m.get("type") == "literal":
        idx = text.find(pattern)
        if idx < 0:
            return None
        return {"quote": pattern, "version": None}
    try:
        # MULTILINE: 헤더/쿠키처럼 여러 라인으로 구성된 자산에서 ^/$ 앵커가 라인 단위로 동작.
        rx = re.compile(pattern, re.MULTILINE)
    except re.error as e:
        print(f"[!] bad regex in {sig.get('id')}: {e}", file=sys.stderr)
        return None
    mo = rx.search(text)
    if not mo:
        return None
    version = None
    if "version" in (mo.groupdict() or {}):
        version = mo.group("version")
    quote = mo.group(0)
    if len(quote) > 200:
        quote = quote[:200]
    return {"quote": quote, "version": version}


def _ver_tuple(v):
    parts = []
    for p in str(v).split("."):
        if p.isdigit():
            parts.append(int(p))
        else:
            parts.append(0)
            break
    return tuple(parts)


def apply_werkzeug_flask_map(findings):
    """confirmed Werkzeug 버전 → Flask 릴리스 시기(inferred 범위) 매핑 (T11).

    정확한 Flask 버전은 아니며 '시기' 추정이다. 근거는 Werkzeug 근거와 동일 헤더에 바인딩.
    """
    mpath = os.path.join(ROOT, "harness", "signatures", "maps", "werkzeug-flask.json")
    if not os.path.exists(mpath):
        return 0
    with open(mpath, encoding="utf-8") as f:
        entries = json.load(f)["map"]
    entries = sorted(entries, key=lambda e: _ver_tuple(e["werkzeug_min"]))

    added = 0
    for f in list(findings):
        if f.get("product") != "Werkzeug" or f.get("provenance") != "confirmed":
            continue
        v = _ver_tuple(f.get("version"))
        if not v:
            continue
        chosen = None
        for e in entries:
            if v >= _ver_tuple(e["werkzeug_min"]):
                chosen = e
        if chosen is None:
            continue
        fid = max([int(x["finding_id"].split("-")[-1]) for x in findings] or [0]) + 1
        findings.append({
            "finding_id": f"FND-{fid:03d}",
            "generated_by": "fingerprint.py",
            "asset_kind": f.get("asset_kind", "header"),
            "product": "Flask",
            "version": "unknown",
            "version_bound": chosen["flask_version_bound"],
            "provenance": "inferred",
            "evidence_path": f.get("evidence_path"),
            "evidence_quote": f.get("evidence_quote"),
            "asset_sha256": f.get("asset_sha256"),
            "reasoning": (f"map: Werkzeug {f.get('version')} → Flask 릴리스 시기 "
                          f"(maps/werkzeug-flask.json): {chosen['note']}"),
            "verified_by": ["fingerprint.py:map:werkzeug-flask"],
            "report_eligible": False,
        })
        added += 1
    return added


def apply_django_hash_db(manifest, findings):
    """Django admin 정적 자산 해시 → 버전 (T11).

    자산 sha256 이 공식 릴리스에서 추출한 DB 와 일치하면 결정론적 confirmed.
    해시가 여러 버전을 공유하면(login.css 등) 버전은 범위로 표기(제품 정체는 해시로 확정).
    evidence_quote 는 자산의 첫 64바이트(바이트 그대로 실재) — 버전 근거는 자산 해시 일치다.
    """
    mpath = os.path.join(ROOT, "harness", "signatures", "maps", "django-static-hashes.json")
    if not os.path.exists(mpath):
        return 0
    with open(mpath, encoding="utf-8") as f:
        db = json.load(f)["hashes"]

    added = 0
    resolved_refs = set()
    for asset in manifest.get("assets", []):
        kind = asset.get("asset_kind", "")
        src = asset.get("source_url", "")
        if kind not in ("css", "js") or "/static/admin/" not in src:
            continue
        sha = asset.get("asset_sha256")
        if sha not in db:
            continue
        resolved_refs.add(asset.get("raw_ref"))
        rec = db[sha]
        versions = rec.get("versions", [])
        raw_ref = asset.get("raw_ref")
        if not raw_ref:
            continue
        raw_path = os.path.join(ROOT, raw_ref)
        if not os.path.exists(raw_path):
            continue
        with open(raw_path, "rb") as f:
            head = f.read(64)

        fid = max([int(x["finding_id"].split("-")[-1]) for x in findings] or [0]) + 1
        if len(versions) == 1:
            version, vbound, prov = versions[0], "UNSET", "confirmed"
        else:
            version, prov = "unknown", "confirmed"  # 해시 일치 = Django 정적 자산 확정
            vbound = f"{min(versions)}-{max(versions)}"
        findings.append({
            "finding_id": f"FND-{fid:03d}",
            "generated_by": "fingerprint.py",
            "asset_kind": kind,
            "product": "Django",
            "version": version,
            "version_bound": vbound,
            "provenance": prov,
            "evidence_path": raw_ref,
            "evidence_quote": head.decode("utf-8", "replace"),
            "asset_sha256": sha,
            "reasoning": (f"map: admin 정적 자산 sha256 이 Django 릴리스 해시 DB 와 일치 "
                          f"(maps/django-static-hashes.json): {rec['asset']} → {versions}"),
            "verified_by": ["fingerprint.py:map:django-static-hashes"],
            "report_eligible": False,
        })
        added += 1

    # 해시로 결정된 자산의 모순적인 unidentified/unknown 발견을 제거(같은 자산에 확정 근거가 생김)
    if resolved_refs:
        findings[:] = [f for f in findings
                       if not (f.get("provenance") == "unknown"
                               and f.get("evidence_path") in resolved_refs)]
    return added


FOREIGN_PREFIXES = (
    "active_recon.py:", "extract_assets.py:", "discover_vhost.py:",
    "discover_dns.py:", "aws_recon.py:", "fallback-inference:", "second-pass", "cariddi",
)


def _is_foreign(f):
    """fingerprint 가 소유하지 않은 발견인가 (T18 — 멱등 병합).

    다른 스크립트가 만들거나(verified_by 의 외부 출처 prefix) 터치한(second-pass) 발견은
    fingerprint 재실행이 파괴하면 안 되므로 보존한다.
    """
    if f.get("generated_by") not in (None, "fingerprint.py"):
        return True
    vb = f.get("verified_by") or []
    return any(str(v).startswith(FOREIGN_PREFIXES) for v in vb)


def load_existing(host):
    fpath = os.path.join(ROOT, "targets", host, "findings.json")
    if not os.path.exists(fpath):
        return {"findings": [], "unmatched": []}, fpath
    with open(fpath, encoding="utf-8") as f:
        try:
            doc = json.load(f)
        except json.JSONDecodeError:
            doc = {}
    return {"findings": doc.get("findings", []), "unmatched": doc.get("unmatched", [])}, fpath


def merge_idempotent(existing, new_findings, new_unmatched):
    """기존 findings.json 과 신규 fingerprint 산출물을 멱등 병합 (T18).

    - 외부 출처/터치된 발견(active_recon, extract_assets, discover_*, fallback-inference,
      second-pass, cariddi 등)은 **보존**한다.
    - fingerprint 소유 발견은 신규 산출로 교체한다.
    - 보존 발견이 있는 자산(evidence_path)은 fingerprint 의 unknown/unmatched 재생성을
      건너뛰어 fallback 결과 등을 되돌리지 않는다.
    - (evidence_path, product) 가 보존 발견과 같으면 신규 signature 발견도 건너뛴다
      (second-pass 판정 등이 덮어쓰이지 않게).
    """
    preserved = [f for f in existing["findings"] if _is_foreign(f)]
    preserved_paths = {f.get("evidence_path") for f in preserved if f.get("evidence_path")}
    preserved_prods = {(f.get("evidence_path"), f.get("product"))
                       for f in preserved if f.get("evidence_path")}

    kept_new = []
    for f in new_findings:
        if f.get("evidence_path") in preserved_paths and f.get("product") == "unidentified":
            continue  # fallback 등이 해결한 자산에 unknown 을 다시 만들지 않는다
        if (f.get("evidence_path"), f.get("product")) in preserved_prods:
            continue  # second-pass 등이 확정/강등한 발견을 재생성하지 않는다
        kept_new.append(f)
    new_unmatched = [u for u in new_unmatched if u.get("evidence_path") not in preserved_paths]

    return preserved + kept_new, new_unmatched


def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministic fingerprinting")
    ap.add_argument("target", help="host label (targets/<host>/)")
    args = ap.parse_args()

    tdir = os.path.join(ROOT, "targets", args.target)
    mpath = os.path.join(tdir, "captures", "manifest.json")
    if not os.path.exists(mpath):
        print(f"[!] manifest not found: {mpath} — run collect_web.py first", file=sys.stderr)
        return 2
    with open(mpath, encoding="utf-8") as f:
        manifest = json.load(f)

    signatures = load_signatures()
    print(f"[*] {len(signatures)} signatures loaded")

    existing, fpath = load_existing(args.target)
    preserved_paths = {f.get("evidence_path") for f in existing["findings"]
                       if _is_foreign(f) and f.get("evidence_path")}
    preserved_prods = {(f.get("evidence_path"), f.get("product"))
                       for f in existing["findings"]
                       if _is_foreign(f) and f.get("evidence_path")}

    findings = []
    unmatched = []
    max_fid = max([int(f["finding_id"].split("-")[-1]) for f in existing["findings"]
                   if f["finding_id"].split("-")[-1].isdigit()] or [0])
    fid = max_fid + 1
    for asset in manifest.get("assets", []):
        cf = content_for(asset)
        if cf is None:
            continue
        match_ref, text, raw_triple, norm_triple = cf
        kind = asset.get("asset_kind", "other")
        asset_hit = False
        for sig in signatures:
            kinds = sig.get("asset_kinds", [])
            if kinds and kind not in kinds:
                continue
            res = match_signature(sig, text)
            if not res:
                continue
            # 근거 바인딩: quote의 UTF-8 바이트가 실제로 존재하는 파일에 evidence를 건다(원본 우선).
            # 어느 파일에도 바이트로 존재하지 않으면(beautify 변형 등) 근거로 쓸 수 없어 건너뛴다.
            quote = res["quote"]
            bound = bind_evidence(quote, raw_triple, norm_triple)
            if bound is None:
                continue
            ev, ev_sha256 = bound
            if (ev, sig["_product"]) in preserved_prods:
                continue  # 외부 출처가 이미 이 (자산, 제품)을 확정/강등함(T18)
            asset_hit = True
            implies = sig.get("implies", {})
            version = res["version"]
            if version:
                provenance = "confirmed"  # 정확 버전 문자열이 파일에 실재
                version_bound = "UNSET"
            else:
                provenance = implies.get("provenance", "inferred")
                version = "unknown"
                version_bound = implies.get("version_bound", "UNSET")
            findings.append({
                "finding_id": f"FND-{fid:03d}",
                "generated_by": "fingerprint.py",
                "asset_kind": kind,
                "product": sig["_product"],
                "version": version,
                "version_bound": version_bound,
                "provenance": provenance,
                "evidence_path": ev,
                "evidence_quote": quote,
                "asset_sha256": ev_sha256,
                "reasoning": f"signature {sig['id']}: {sig.get('note', '')}",
                "verified_by": ["fingerprint.py:" + sig["id"]],
                "report_eligible": False,
            })
            fid += 1
        if not asset_hit and kind in ("js", "css", "html", "header", "cookie"):
            if match_ref in preserved_paths:
                continue  # 외부 출처가 이미 해결한 자산 — unknown/unmatched 재생성 금지(T18)
            unmatched.append({
                "asset_id": asset.get("asset_id"),
                "source_url": asset.get("source_url"),
                "asset_kind": kind,
                "evidence_path": match_ref,
                "asset_sha256": asset.get("asset_sha256", "UNSET"),
                "note": "no deterministic signature matched — AI fallback 추론 대상",
            })
            # 'unknown' 은 1급 출력이다. 매칭 실패 자산도 명시적 unknown 발견으로 남긴다
            # (게이트: findings 는 비어있으면 안 됨). AI fallback 이 업그레이드하는 대상.
            # ⚠️ 해시는 evidence_path(실제 바인딩 파일)에서 재계산 — 정규화본이면 정규화본 해시.
            try:
                ev_bytes = open(os.path.join(ROOT, match_ref), "rb").read()
                ev_sha = _sha256_bytes(ev_bytes)
            except OSError:
                ev_sha = asset.get("asset_sha256", "UNSET")
            findings.append({
                "finding_id": f"FND-{fid:03d}",
                "generated_by": "fingerprint.py",
                "asset_kind": kind,
                "product": "unidentified",
                "version": "unknown",
                "version_bound": "UNSET",
                "provenance": "unknown",
                "evidence_path": match_ref,
                "evidence_quote": "UNSET",
                "asset_sha256": ev_sha,
                "reasoning": "no deterministic signature matched — 판단 불가(unknown)",
                "verified_by": [],
                "report_eligible": False,
            })
            fid += 1

    n_wf = apply_werkzeug_flask_map(findings)
    n_dj = apply_django_hash_db(manifest, findings)
    findings, unmatched = merge_idempotent(existing, findings, unmatched)

    out = {
        "target": args.target,
        "generated_by": "fingerprint.py",
        "produced_by": manifest.get("produced_by", "fingerprint.py"),
        "findings": findings,
        "unmatched": unmatched,
    }
    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    conf = sum(1 for x in findings if x["provenance"] == "confirmed")
    inf = sum(1 for x in findings if x["provenance"] == "inferred")
    gss = sum(1 for x in findings if x["provenance"] == "guess")
    print(f"[*] findings: {len(findings)} (confirmed={conf} inferred={inf} guess={gss}), unmatched={len(unmatched)}")
    print(f"[*] written: {os.path.relpath(fpath, ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
