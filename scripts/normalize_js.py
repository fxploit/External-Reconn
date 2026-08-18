#!/usr/bin/env python3
"""JS 정규화 — 지문 추출용.

목표는 완벽 복호화가 아니라 '기계가 제품·버전을 매칭할 수 있게' 정규화하는 것이다:
 1) eval-packed(Dean Edwards p,a,c,k,e,d) 언패킹
 2) beautify(줄바꿈 삽입) — jsbeautifier가 있으면 사용, 없으면 경량 폴백

manifest.json의 js 자산을 읽어 captures/normalized/ 에 정규화본을 쓰고,
manifest 각 항목에 normalized_ref / unpacked 플래그를 덧붙인다.

Usage:
    python scripts/normalize_js.py <host>
"""
import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import sys as _sys
_sys.path.insert(0, os.path.join(ROOT, "scripts"))
from lib.engagement import append_event  # noqa: E402

try:
    import jsbeautifier  # type: ignore
    _HAS_JSB = True
except Exception:  # noqa: BLE001
    _HAS_JSB = False


def unbase_factory(radix: int):
    digits = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    table = {c: i for i, c in enumerate(digits)}

    def unbase(token: str) -> int:
        if radix <= 36:
            try:
                return int(token, radix)
            except ValueError:
                pass
        n = 0
        for ch in token:
            n = n * radix + table.get(ch, 0)
        return n

    return unbase


def unpack_packed(source: str):
    """Dean Edwards p,a,c,k,e,d 언패커. 실패하면 (source, False)."""
    m = re.search(
        r"\}\s*\(\s*'(.*?)'\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*'(.*?)'\.split\('\|'\)",
        source,
        re.DOTALL,
    )
    if not m:
        return source, False
    payload, radix, count, symtab_raw = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)
    payload = payload.replace("\\'", "'").replace("\\\\", "\\")
    symtab = symtab_raw.split("|")
    unbase = unbase_factory(radix)

    def repl(match: "re.Match") -> str:
        word = match.group(0)
        idx = unbase(word)
        if 0 <= idx < len(symtab) and symtab[idx]:
            return symtab[idx]
        return word

    unpacked = re.sub(r"\b\w+\b", repl, payload)
    unpacked = unpacked.replace("\\n", "\n").replace('\\"', '"')
    return unpacked, True


def decode_bytes(data: bytes) -> str:
    """한글 등 인코딩을 견고하게 디코딩(UTF-8-BOM → UTF-8 → CP949 → latin-1)."""
    for enc in ("utf-8-sig", "utf-8", "cp949"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1")


def light_beautify(code: str) -> str:
    """jsbeautifier 없을 때의 경량 폴백 — 지문 추출엔 충분한 수준."""
    code = re.sub(r";(?![\n\s])", ";\n", code)
    code = code.replace("{", "{\n").replace("}", "\n}\n")
    return code


def beautify(code: str) -> str:
    if _HAS_JSB:
        try:
            return jsbeautifier.beautify(code)
        except Exception:  # noqa: BLE001
            pass
    return light_beautify(code)


def main() -> int:
    ap = argparse.ArgumentParser(description="Normalize JS for fingerprinting")
    ap.add_argument("target", help="host label (targets/<host>/)")
    args = ap.parse_args()

    tdir = os.path.join(ROOT, "targets", args.target)
    mpath = os.path.join(tdir, "captures", "manifest.json")
    if not os.path.exists(mpath):
        print(f"[!] manifest not found: {mpath} — run collect_web.py first", file=sys.stderr)
        return 2

    with open(mpath, encoding="utf-8") as f:
        manifest = json.load(f)

    norm_dir = os.path.join(tdir, "captures", "normalized")
    os.makedirs(norm_dir, exist_ok=True)

    n_unpacked = 0
    n_done = 0
    for asset in manifest.get("assets", []):
        if asset.get("asset_kind") != "js" or not asset.get("raw_ref"):
            continue
        raw_path = os.path.join(ROOT, asset["raw_ref"])
        if not os.path.exists(raw_path):
            continue
        with open(raw_path, "rb") as f:
            code = decode_bytes(f.read())

        unpacked = False
        if "eval(function(p,a,c,k,e," in code.replace(" ", ""):
            code, unpacked = unpack_packed(code)
            if unpacked:
                n_unpacked += 1

        pretty = beautify(code)
        name = os.path.basename(raw_path)
        if not name.endswith(".js"):
            name += ".js"
        out_path = os.path.join(norm_dir, name)
        # 표준 UTF-8/LF로 저장(Windows CRLF 변환 방지) — 해시 재현성과 바이트 대조 일관성 확보.
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(pretty)

        asset["normalized_ref"] = os.path.relpath(out_path, ROOT).replace("\\", "/")
        asset["unpacked"] = unpacked
        n_done += 1
        flag = " (unpacked)" if unpacked else ""
        print(f"[+] normalized {asset['asset_id']}{flag} -> {asset['normalized_ref']}")

    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    beautifier = "jsbeautifier" if _HAS_JSB else "light-fallback"
    print(f"\n[*] normalized {n_done} JS asset(s), {n_unpacked} unpacked (beautifier: {beautifier})")
    if not _HAS_JSB:
        print("[i] `pip install jsbeautifier` 하면 더 정확한 정규화가 됩니다.")
    append_event(args.target, {"event": "normalize", "produced_by": "normalize_js.py",
                               "manifest_ref": os.path.relpath(mpath, ROOT).replace("\\", "/"),
                               "normalized_count": n_done})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
