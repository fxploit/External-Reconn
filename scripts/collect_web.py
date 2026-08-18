#!/usr/bin/env python3
"""Passive web recon collector.

페이지 접속으로 자연히 오가는 자산만 수집한다(수동/저위험):
HTTP 헤더, HTML, 참조된 JS/CSS, 쿠키, 파비콘.
각 자산을 targets/<host>/captures/raw/ 에 저장하고 sha256을 manifest.json에 기록한다.

의존성 없음(stdlib urllib). 상태를 바꾸지 않으므로 능동 정찰 GO가 필요 없다.
단, 결과는 Observation으로 보존한다(AGENTS.md).

Usage:
    python scripts/collect_web.py <url> --target <host>
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from lib.engagement import append_event  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UA = "recon-harness/0.1 (passive collector)"

# WSTG-INFO-03: 웹서버가 스스로 노출하는 표준 메타/정책 파일. 고정 목록(브루트포스 아님),
# 진입 오리진에서 1회씩만 GET — 표준적·저위험이라 패시브로 취급한다(경계 논의는 README).
METAFILES = [
    "/robots.txt",
    "/sitemap.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/humans.txt",
]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AssetParser(HTMLParser):
    """HTML에서 script src / link href(css, icon) / a href(크롤 링크)를 추출한다."""

    def __init__(self):
        super().__init__()
        self.scripts = []
        self.styles = []
        self.icons = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "link":
            rel = (a.get("rel") or "").lower()
            href = a.get("href")
            if not href:
                return
            if "stylesheet" in rel:
                self.styles.append(href)
            elif "icon" in rel:
                self.icons.append(href)
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])


def fetch(url: str, timeout: int = 20, host: str = None):
    """(status, headers_dict, raw_headers, body, err) 반환.

    raw_headers 는 응답 순서·중복(다중 Set-Cookie)을 보존한 (Name, Value) 리스트다.
    T9(헤더·쿠키 1급 자산)부터 이 리스트로 __headers__.txt/__cookies__.txt 를 만든다.
    """
    fetch.request_count = getattr(fetch, "request_count", 0) + 1
    headers = {"User-Agent": UA}
    if host:
        # 평문 HTTP vhost: URL 은 IP 로 접속하되 Host 헤더를 vhost 로 덮어쓴다.
        headers["Host"] = host
    req = Request(url, headers=headers)
    try:
        resp = urlopen(req, timeout=timeout)
        body = resp.read()
        raw = list(resp.getheaders())
        return resp.status, dict(raw), raw, body, None
    except HTTPError as e:
        body = e.read() if hasattr(e, "read") else b""
        raw = list(e.headers.items()) if e.headers else []
        return e.code, dict(raw), raw, body, None
    except URLError as e:
        return None, {}, [], b"", f"URLError: {e.reason}"
    except Exception as e:  # noqa: BLE001
        return None, {}, [], b"", f"{type(e).__name__}: {e}"


def kind_for(url: str, content_type: str) -> str:
    ct = (content_type or "").lower()
    path = urlparse(url).path.lower()
    if "javascript" in ct or path.endswith(".js") or path.endswith(".mjs"):
        return "js"
    if path.endswith(".map"):
        return "sourcemap"
    if "css" in ct or path.endswith(".css"):
        return "css"
    if "html" in ct or path.endswith((".html", ".htm", "/")):
        return "html"
    if "icon" in ct or path.endswith((".ico", ".png", ".svg")):
        return "favicon"
    return "other"


def sourcemap_url_from(body: bytes) -> str:
    """JS 본문의 //# sourceMappingURL= 을 추출(T21). 없으면 None."""
    try:
        text = body.decode("utf-8", "replace")
    except Exception:
        return None
    m = re.search(r"(?://|/\*)[#@]\s*sourceMappingURL=(\S+)", text)
    return m.group(1).strip().rstrip("*/").strip() if m else None


def safe_name(url: str, idx: int, kind: str) -> str:
    base = os.path.basename(urlparse(url).path) or f"{kind}_{idx}"
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    if not base or base in (".", ".."):
        base = f"{kind}_{idx}"
    ext = {"js": ".js", "css": ".css", "html": ".html"}.get(kind, "")
    if ext and not base.endswith(ext):
        base += ext
    return f"{idx:02d}_{base}"


def save(raw_dir: str, name: str, data: bytes) -> str:
    path = os.path.join(raw_dir, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


def rel(path: str) -> str:
    return os.path.relpath(path, ROOT).replace("\\", "/")


def main() -> int:
    ap = argparse.ArgumentParser(description="Passive web recon collector")
    ap.add_argument("url")
    ap.add_argument("--target", required=True, help="host label for targets/<host>/")
    ap.add_argument("--host", default=None,
                    help="평문 HTTP vhost: URL은 IP로 두고 Host 헤더를 이 값으로 덮어씀")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--max-assets", type=int, default=60)
    ap.add_argument("--depth", type=int, default=1,
                    help="크롤 깊이(T16, 기본 1=진입+참조. 상한 3). 상향은 요청량 증가 — 명시적 선택")
    ap.add_argument("--skip-metafiles", action="store_true",
                    help="WSTG-INFO-03 표준 메타파일(robots/sitemap/security.txt 등) 수집 생략")
    args = ap.parse_args()
    args.depth = max(0, min(args.depth, 3))
    fetch.request_count = 0

    tdir = os.path.join(ROOT, "targets", args.target)
    raw_dir = os.path.join(tdir, "captures", "raw")
    obs_dir = os.path.join(tdir, "captures", "observation")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(obs_dir, exist_ok=True)

    manifest = {
        "target": args.target,
        "entry_url": args.url,
        "collected_at": now_iso(),
        "collector": UA,
        "produced_by": os.environ.get("RECON_PRODUCED_BY", os.path.basename(__file__)),
        "collection_mode": "static",
        "host_override": args.host,
        "crawl_depth": args.depth,
        "request_budget": {"planned_metafiles": 0 if args.skip_metafiles else len(METAFILES),
                           "actual_requests": 0},
        "assets": [],
    }

    entry_netloc = urlparse(args.url).netloc
    print(f"[*] fetching entry: {args.url}" + (f" (Host: {args.host})" if args.host else "") +
          f" (depth={args.depth})")
    status, headers, raw_headers, body, err = fetch(args.url, args.timeout, host=args.host)
    if err:
        print(f"[!] entry fetch failed: {err}", file=sys.stderr)
        # 실패도 Observation으로 보존 (invariants: 실패를 삭제하지 않는다)
        with open(os.path.join(obs_dir, "entry-error.txt"), "w", encoding="utf-8") as f:
            f.write(f"url: {args.url}\nerror: {err}\nat: {now_iso()}\n")
        return 2

    # ── 응답 헤더/쿠키를 1급 매칭 자산으로 등록 (T9 substrate) ──────────────
    # 헤더: 응답 순서·중복 보존 (Name: Value 라인) → asset_kind: header
    header_bytes = "".join(f"{k}: {v}\n" for k, v in raw_headers).encode("utf-8")
    hdr_path = save(raw_dir, "__headers__.txt", header_bytes)
    manifest["assets"].append({
        "asset_id": "AST-HDR",
        "source_url": args.url + "#headers",
        "asset_kind": "header",
        "http_status": status,
        "content_type": "text/plain",
        "raw_ref": rel(hdr_path),
        "asset_sha256": sha256_hex(header_bytes),
    })
    # 쿠키: Set-Cookie 값 원문은 raw/(gitignore)에만. 지문은 이름·플래그·형식만 사용.
    set_cookies = [v for k, v in raw_headers if k.lower() == "set-cookie"]
    if set_cookies:
        cookie_bytes = "\n".join(set_cookies).replace("\r", "").encode("utf-8")
        ck_path = save(raw_dir, "__cookies__.txt", cookie_bytes)
        manifest["assets"].append({
            "asset_id": "AST-CK",
            "source_url": args.url + "#cookies",
            "asset_kind": "cookie",
            "http_status": status,
            "content_type": "text/plain",
            "raw_ref": rel(ck_path),
            "asset_sha256": sha256_hex(cookie_bytes),
        })

    def _save_asset(url, kind, st, ctype, data, asset_id):
        name = safe_name(url, int(asset_id.split("-")[-1]), kind)
        p = save(raw_dir, name, data)
        manifest["assets"].append({
            "asset_id": asset_id,
            "source_url": url,
            "asset_kind": kind,
            "http_status": st,
            "content_type": ctype,
            "raw_ref": rel(p),
            "asset_sha256": sha256_hex(data),
        })
        return rel(p)

    entry_kind = kind_for(args.url, headers.get("Content-Type", ""))
    _save_asset(args.url, entry_kind, status, headers.get("Content-Type", ""), body, "AST-000")

    # ── WSTG-INFO-03: 표준 메타/정책 파일 (고정 목록, 진입 오리진, 1회씩) ─────────
    # 존재하는 것만 1급 자산으로 등록 → extract_assets/fingerprint 가 이어서 마이닝한다.
    # 부재(4xx/5xx)·실패도 삭제하지 않고 observation 에 남긴다(invariants).
    if not args.skip_metafiles:
        mf_missing = []
        mf_found = 0
        for mi, mpath_rel in enumerate(METAFILES):
            mf_url = urljoin(args.url, mpath_rel)
            mf_st, mf_hd, mf_rh, mf_body, mf_err = fetch(mf_url, args.timeout, host=args.host)
            if mf_err:
                mf_missing.append(f"{mpath_rel}\terror\t{mf_err}")
                continue
            if mf_st and 200 <= mf_st < 300 and mf_body:
                mf_kind = kind_for(mf_url, mf_hd.get("Content-Type", "")) or "metafile"
                _save_asset(mf_url, "metafile", mf_st, mf_hd.get("Content-Type", ""),
                            mf_body, f"AST-MF-{mi:02d}")
                # 자산 종류는 metafile 로 통일하되, 콘텐츠 종류 힌트는 source_url 로 남긴다.
                manifest["assets"][-1]["content_kind_hint"] = mf_kind
                print(f"[+] {'metafile':8s} {mf_url} ({mf_st}) -> raw")
                mf_found += 1
            else:
                mf_missing.append(f"{mpath_rel}\t{mf_st}")
        if mf_missing:
            with open(os.path.join(obs_dir, "metafiles-absent.txt"), "w", encoding="utf-8") as f:
                f.write("# WSTG-INFO-03 metafiles: 부재/실패 (path<TAB>status[/error])\n")
                f.write("\n".join(mf_missing) + "\n")
        print(f"[i] metafiles: {mf_found} present, {len(mf_missing)} absent/failed")

    # ── 깊이 제한 크롤 (T16) — 동일 netloc 내부만 따라가고, 외부 링크는 기록만 ──
    seen = {args.url}
    seen_hashes = set()
    external = []
    queue = [(args.url, entry_kind, body, 0)]
    idx = 1
    while queue and idx <= args.max_assets:
        url, kind, data, depth = queue.pop(0)
        if url != args.url:
            asset_host = args.host if (args.host and urlparse(url).netloc == entry_netloc) else None
            st, hd, rh, body2, e = fetch(url, args.timeout, host=asset_host)
            if e:
                manifest["assets"].append({
                    "asset_id": f"AST-{idx:03d}", "source_url": url, "asset_kind": kind,
                    "http_status": None, "error": e, "raw_ref": None, "asset_sha256": None,
                })
                idx += 1
                continue
            h2 = sha256_hex(body2)
            if h2 in seen_hashes:
                continue  # 동일 바디 중복 저장 방지(fetch 후 실제 바디 기준)
            seen_hashes.add(h2)
            kind = kind_for(url, hd.get("Content-Type", "")) or kind
            p = _save_asset(url, kind, st, hd.get("Content-Type", ""), body2, f"AST-{idx:03d}")
            print(f"[+] {kind:8s} {url} -> {p}")
            idx += 1
            data = body2
            # source map 수집 (T21): JS 에 sourceMappingURL 이 있으면 .map 도 자산으로
            if kind == "js" and idx <= args.max_assets:
                sm = sourcemap_url_from(body2)
                if sm:
                    sm_url = urljoin(url, sm)
                    if sm_url not in seen and urlparse(sm_url).netloc == entry_netloc:
                        seen.add(sm_url)
                        sm_st, sm_hd, sm_rh, sm_body, sm_err = fetch(sm_url, args.timeout,
                                                                     host=asset_host)
                        if not sm_err and sm_body:
                            sm_kind = "sourcemap"
                            sm_path = _save_asset(sm_url, sm_kind, sm_st,
                                                  sm_hd.get("Content-Type", ""), sm_body,
                                                  f"AST-{idx:03d}")
                            print(f"[+] {'sourcemap':8s} {sm_url} -> {sm_path}")
                            idx += 1

        if depth < args.depth and kind == "html":
            parser = AssetParser()
            try:
                parser.feed(data.decode("utf-8", "replace"))
            except Exception as e:  # noqa: BLE001
                print(f"[!] html parse warning: {e}", file=sys.stderr)
            refs = [("js", urljoin(url, s)) for s in parser.scripts]
            refs += [("css", urljoin(url, s)) for s in parser.styles]
            refs += [("favicon", urljoin(url, s)) for s in parser.icons]
            refs += [("html", urljoin(url, s)) for s in parser.links]
            if not parser.icons:
                refs.append(("favicon", urljoin(url, "/favicon.ico")))
            for hint_kind, u in refs:
                if u in seen or len(seen) > args.max_assets * 4:
                    continue
                seen.add(u)
                if urlparse(u).netloc == entry_netloc:
                    queue.append((u, hint_kind, b"", depth + 1))
                elif u.startswith(("http://", "https://")):
                    external.append(u)  # 외부 도메인은 기록만 (미크롤)

    if external:
        ext_path = os.path.join(obs_dir, "external-links.txt")
        with open(ext_path, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(set(external))) + "\n")
        print(f"[i] 외부 도메인 링크 {len(set(external))}건 기록만 함(미크롤): "
              f"{os.path.relpath(ext_path, ROOT)}")

    mpath = os.path.join(tdir, "captures", "manifest.json")
    with open(mpath, "w", encoding="utf-8") as f:
        manifest["request_budget"]["actual_requests"] = fetch.request_count
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    print(f"\n[*] {len([a for a in manifest['assets'] if a.get('raw_ref')])} assets saved (depth={args.depth})")
    print(f"[*] manifest: {rel(mpath)}")
    append_event(args.target, {"event": "collect", "produced_by": manifest["produced_by"],
                               "manifest_ref": rel(mpath), "asset_count": len(manifest["assets"])})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
