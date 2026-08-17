#!/usr/bin/env python3
"""난독화 JS 심층 해석 — 숨은 정보(엔드포인트·시크릿·버전·경로) 수집 (T21).

기존 파이프라인의 normalize(문자셋 디코딩+eval-packer+beautify)를 **심화**한다:
 1) 유형 탐지 → 매칭 디코더 라우팅:
    - eval-packer(p,a,c,k,e,d) — normalize 의 언패커 재사용
    - javascript-obfuscator string-array(배열+index) — 휴리스틱 언패커(rotate/복합형은 제외)
    - 범용 인코딩 블롭: 문자열 리터럴의 base64/hex/URL-encoded 재귀 디코딩(가역성 체크)
 2) source map 수집·복원: 수집기가 `//# sourceMappingURL=` → `.map` 을 자산으로 등록하면
    원본 소스(sourcesContent)를 복원해 자산으로 등록(가장 깨끗한 디오브푸스케이션).
 3) 디코드본 재분석: 산출물을 captures/decoded/ 에 표준 UTF-8 저장·해시하고, fingerprint/extract 를
    재적용해 숨었던 엔드포인트·버전을 발견.

환각 통제:
 - 디코드본은 **파생물**이다. 각 자산에 `derived_from`(원본 asset_id) + `decoder`(사용 디코더) 기록.
 - finding 근거는 디코드 파일(실재)에 바인딩, asset_sha256 은 디코드 파일에서 재계산(게이트 일치).
 - 인코딩 디코딩은 **가역성/일관성 체크**(re-encode 대조)로 오디코드 억제, 비가독 결과는 폐기.
 - 못 뚫으면(rotate/커스텀) `unknown` 보존 — 억지 복원 금지. 실패/건너뜀도 Observation 보존.

Usage:
    python scripts/deobfuscate.py <host>
"""
import argparse
import base64
import json
import os
import re
import subprocess
import sys
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect_web import now_iso, rel, sha256_hex  # noqa: E402
from normalize_js import unpack_packed  # noqa: E402

DECODED_DIR = "captures/decoded"
PRINTABLE = re.compile(r"^[\x09\x0a\x0d\x20-\x7e\xa0-\xff]*$")
MAX_RECURSE = 3


def _utf8_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def decode_bytes(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "cp949"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1")


# ── 1. JS 이스케이프(\xNN, \uNNNN) — 정확, 원문 그대로 변환 ─────────────────────
def unescape_js(text: str) -> str:
    out = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)
    out = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), out)
    return out


# ── 2. string-array (javascript-obfuscator 단순형) 휴리스틱 언패커 ──────────────
def unpack_string_array(text: str):
    """var _0x.. = ['..',...]; function _0x..(x){... return _0x..[x - 0xN] ...} 형태.

    rotate("crazy"): 배열을 런타임에 push/splice/shift 로 섞는 변형은 미지원 — (원문, False).
    """
    m = re.search(r"var\s+(_0x[a-f0-9]+)\s*=\s*\[(.*?)\]\s*;", text)
    if not m:
        return text, False
    arr_name = m.group(1)
    items = re.findall(r"'((?:\\.|[^'\\])*)'|\"((?:\\.|[^\"\\])*)\"", m.group(2))
    arr = []
    for a, b in items:
        s = a if a != "" else b
        s = s.replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")
        s = re.sub(r"\\x([0-9a-fA-F]{2})", lambda mm: chr(int(mm.group(1), 16)), s)
        s = re.sub(r"\\u([0-9a-fA-F]{4})", lambda mm: chr(int(mm.group(1), 16)), s)
        arr.append(s)
    if not arr:
        return text, False
    # rotate 변형(배열 런타임 변조) 감지 → 미지원
    if re.search(r"\b%s\b[^;]{0,120}\b(push|splice|shift|unshift)\b" % re.escape(arr_name), text):
        return text, False

    for fm in re.finditer(r"function\s+(_0x[a-f0-9]+)\s*\(\s*([a-zA-Z_$][\w$]*)\s*\)\s*\{", text):
        fname = fm.group(1)
        body = text[fm.end():fm.end() + 600]
        rm = re.search(r"return\s+%s\s*\[\s*([a-zA-Z_$][\w$]*)\s*(?:-\s*(0x[0-9a-f]+|\d+))?\s*\]"
                       % re.escape(arr_name), body)
        if not rm:
            continue
        offset = int(rm.group(2), 0) if rm.group(2) else 0

        def repl(mo):
            idx = int(mo.group(1), 0) - offset
            return arr[idx] if 0 <= idx < len(arr) else mo.group(0)

        out = re.sub(r"\b%s\(\s*(0x[0-9a-f]+|\d+)\s*\)" % re.escape(fname), repl, text)
        return out, out != text
    return text, False


# ── 3. 범용 인코딩 블롭(base64/hex/url) 재귀 디코딩 — 가역성 체크 ───────────────
def is_printable(raw: bytes) -> bool:
    if not raw:
        return False
    return bool(PRINTABLE.match(raw.decode("latin-1"))) and len(raw) >= 4


def decode_candidate(s: str, depth=0):
    """문자열 하나의 디코딩 후보(들). (인코딩, 디코드텍스트) 목록."""
    if depth > MAX_RECURSE or len(s) < 8:
        return []
    out = []
    # base64
    if re.fullmatch(r"[A-Za-z0-9+/]{8,}={0,2}", s):
        try:
            raw = base64.b64decode(s + "=" * (-len(s) % 4))
            if is_printable(raw):
                norm = base64.b64encode(raw).decode("ascii").rstrip("=")
                if norm == s.rstrip("="):  # 가역성 체크
                    txt = raw.decode("utf-8", "replace")
                    out.append(("base64", txt))
        except Exception:
            pass
    # hex
    if len(s) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]{8,}", s):
        try:
            raw = bytes.fromhex(s)
            if is_printable(raw) and raw.hex().lower() == s.lower():
                out.append(("hex", raw.decode("utf-8", "replace")))
        except ValueError:
            pass
    # url-encoded
    if re.search(r"%[0-9a-fA-F]{2}", s):
        try:
            raw = urllib.parse.unquote_to_bytes(s)
            if is_printable(raw):
                out.append(("url", raw.decode("utf-8", "replace")))
        except Exception:
            pass
    # 중첩 인코딩(재귀) — 디코드 결과가 다시 인코딩이면 한 번 더
    nested = []
    for enc, txt in out:
        for e2, t2 in decode_candidate(txt, depth + 1):
            nested.append((f"{enc}:{e2}", t2))
    return out + nested


def extract_encoded_strings(text: str):
    """JS 문자열 리터럴에서 인코딩 블롭을 찾아 (원문, 디코드목록) 수집. 중복 제거."""
    found = {}
    for m in re.finditer(r"""(['"])((?:\\.|(?!\1).)*?)\1""", text, re.DOTALL):
        lit = m.group(2)
        try:
            lit = lit.encode("utf-8").decode("unicode_escape")
        except Exception:
            pass
        if len(lit) < 8:
            continue
        decs = decode_candidate(lit)
        if decs:
            found.setdefault(lit, []).extend(decs)
    return found


# ── 4. source map 복원 ─────────────────────────────────────────────────────────
def restore_sourcemap(asset, raw_bytes, record):
    """sourcemap 자산 → 원본 소스 복원. (파일경로, 디코더설명, 내용) 목록."""
    try:
        data = json.loads(decode_bytes(raw_bytes))
    except json.JSONDecodeError as e:
        record["errors"].append({"asset": asset.get("asset_id"), "reason": f"invalid json: {e}"})
        return []
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    out = []
    for i, (src, content) in enumerate(zip(sources, contents)):
        if not content:
            continue
        name = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(src)) or f"source_{i}"
        out.append((f"{asset.get('asset_id')}_{i:02d}_{name}", "sourcemap:" + src, content))
    return out


def main() -> int:
    _utf8_stdio()
    ap = argparse.ArgumentParser(description="Deobfuscate JS and extract hidden info (T21)")
    ap.add_argument("target", help="host label (targets/<host>/)")
    args = ap.parse_args()

    tdir = os.path.join(ROOT, "targets", args.target)
    mpath = os.path.join(tdir, "captures", "manifest.json")
    if not os.path.exists(mpath):
        print(f"[!] manifest not found: {mpath} — run collect first", file=sys.stderr)
        return 2
    with open(mpath, encoding="utf-8") as f:
        manifest = json.load(f)

    ddir = os.path.join(tdir, DECODED_DIR)
    os.makedirs(ddir, exist_ok=True)

    record = {"kind": "deobfuscate", "target": args.target,
              "finished_at": now_iso(), "decoded": [], "errors": []}
    new_assets = []
    n_js = n_map = 0

    for asset in manifest.get("assets", []):
        kind = asset.get("asset_kind")
        raw_ref = asset.get("raw_ref")
        if not raw_ref or not os.path.exists(os.path.join(ROOT, raw_ref)):
            continue
        with open(os.path.join(ROOT, raw_ref), "rb") as f:
            raw_bytes = f.read()

        if kind == "sourcemap":
            for fname, decoder, content in restore_sourcemap(asset, raw_bytes, record):
                out_path = os.path.join(ddir, fname)
                with open(out_path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(content)
                data = content.encode("utf-8")
                new_assets.append({
                    "asset_id": f"DEC-{len(new_assets):03d}",
                    "source_url": (asset.get("source_url") or "") + "#decoded:" + fname,
                    "asset_kind": "js",
                    "http_status": None,
                    "content_type": "application/javascript",
                    "raw_ref": rel(out_path),
                    "asset_sha256": sha256_hex(data),
                    "derived_from": asset.get("asset_id"),
                    "decoder": decoder,
                })
                record["decoded"].append({"asset": asset.get("asset_id"), "decoder": decoder,
                                          "file": rel(out_path)})
                print(f"[+] sourcemap 복원 {fname} (decoder={decoder})")
                n_map += 1
            continue

        if kind != "js" or asset.get("derived_from"):
            continue
        text = decode_bytes(raw_bytes)
        transforms = []
        out = text
        # 1) 이스케이프
        unesc = unescape_js(out)
        if unesc != out:
            transforms.append("unescape")
            out = unesc
        # 2) eval-packer
        unp, was_packed = unpack_packed(out)
        if was_packed:
            transforms.append("eval-packer")
            out = unp
        # 3) string-array
        unst, was_array = unpack_string_array(out)
        if was_array:
            transforms.append("string-array")
            out = unst

        if transforms:
            base = os.path.basename(raw_ref)
            fname = f"{asset.get('asset_id')}_{base}.decoded.js"
            out_path = os.path.join(ddir, fname)
            with open(out_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(out)
            data = out.encode("utf-8")
            new_assets.append({
                "asset_id": f"DEC-{len(new_assets):03d}",
                "source_url": (asset.get("source_url") or "") + "#decoded:" + ",".join(transforms),
                "asset_kind": "js",
                "http_status": asset.get("http_status"),
                "content_type": "application/javascript",
                "raw_ref": rel(out_path),
                "asset_sha256": sha256_hex(data),
                "derived_from": asset.get("asset_id"),
                "decoder": ",".join(transforms),
            })
            record["decoded"].append({"asset": asset.get("asset_id"),
                                      "decoder": ",".join(transforms), "file": rel(out_path)})
            print(f"[+] deobfuscate {asset['asset_id']} (decoder={','.join(transforms)}) -> {rel(out_path)}")
            n_js += 1

        # 4) 인코딩 블롭 → 디코드 문자열 파일
        pairs = extract_encoded_strings(out)
        if pairs:
            fname = f"{asset.get('asset_id')}_{os.path.basename(raw_ref)}.strings.txt"
            out_path = os.path.join(ddir, fname)
            lines = []
            for lit, decs in pairs.items():
                for enc, txt in decs:
                    lines.append(f"{lit!r} => [{enc}] {txt}")
            content = "\n".join(lines) + "\n"  # 실제 파일에 쓰는 바이트와 해시를 일치(게이트 재검증)
            with open(out_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(content)
            data = content.encode("utf-8")
            new_assets.append({
                "asset_id": f"DEC-{len(new_assets):03d}",
                "source_url": (asset.get("source_url") or "") + "#decoded-strings",
                "asset_kind": "js",
                "http_status": asset.get("http_status"),
                "content_type": "text/plain",
                "raw_ref": rel(out_path),
                "asset_sha256": sha256_hex(data),
                "derived_from": asset.get("asset_id"),
                "decoder": "encoding-blob",
            })
            record["decoded"].append({"asset": asset.get("asset_id"),
                                      "decoder": "encoding-blob", "file": rel(out_path),
                                      "strings": len(pairs)})
            print(f"[+] encoding-blob {len(pairs)}건 -> {rel(out_path)}")
            n_js += 1

    if new_assets:
        manifest.setdefault("assets", []).extend(new_assets)
        with open(mpath, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)

    odir = os.path.join(tdir, "captures", "observation")
    os.makedirs(odir, exist_ok=True)
    opath = os.path.join(odir, f"deobfuscate-{args.target}.json")
    with open(opath, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, ensure_ascii=False)

    print(f"[*] deobfuscate: js/map {n_js + n_map}건 -> {os.path.relpath(ddir, ROOT)}")
    print(f"[*] 기록: {os.path.relpath(opath, ROOT)}")

    # 디코드본 재분석 (fingerprint + extract 재적용)
    if new_assets:
        print("[*] fingerprint/extract 재적용(디코드 자산)...")
        for script in ("normalize_js.py", "fingerprint.py", "extract_assets.py"):
            subprocess.run([sys.executable, os.path.join(ROOT, "scripts", script), args.target],
                           cwd=ROOT, capture_output=True)
    print("[*] 게이트 확인: npm run check -- " + args.target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
