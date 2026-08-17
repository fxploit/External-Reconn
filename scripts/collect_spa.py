#!/usr/bin/env python3
"""SPA(동적) 웹 정찰 수집기 — 헤드리스 브라우저로 페이지를 실제 구동해 자산을 캡처.

정적 collect_web.py 는 진입 HTML의 <script src>/<link> 만 본다. 현대 SPA는 빈 껍데기 HTML을
주고 런타임에 코드 스플릿 청크(chunk-*.js)·XHR·쿠키를 로드하므로, 정적 수집으로는 제품·버전
지문의 대부분을 놓친다. 이 수집기는 Chromium으로 페이지를 실행해 '오가는 모든 응답'을 가로채
captures/raw/ 에 저장하고, 동일한 manifest.json 스키마로 출력한다
(→ normalize_js.py / fingerprint.py 를 그대로 재사용).

vhost 대응: --host-map vhost=ip 를 주면 Chromium 을 --host-resolver-rules 로 띄워
IP 로 접속하되 Host 헤더/TLS SNI 가 올바른 vhost 로 나가게 한다(같은 IP의 다른 가상호스트를
독립 타깃으로 수집).

의존성: playwright (`pip install playwright` 후 `playwright install chromium`).
        미설치 시 안내만 출력하고 종료(정적 collect_web.py 로 폴백 가능).

Usage:
    python scripts/collect_spa.py http://10.10.110.5/ --target 10.10.110.5
    python scripts/collect_spa.py http://intranet.corp.htb/ --target intranet.corp.htb \
        --host-map intranet.corp.htb=10.10.110.5
"""
import argparse
import json
import os
import sys

# 공유 헬퍼는 정적 수집기에서 재사용(중복 방지) — 같은 scripts/ 디렉터리라 import 가능.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collect_web import ROOT, UA, kind_for, now_iso, rel, safe_name, sha256_hex  # noqa: E402


def _require_playwright():
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except Exception:
        print(
            "[!] playwright 미설치. 다음을 실행하세요:\n"
            "      pip install playwright\n"
            "      playwright install chromium\n"
            "    또는 정적 수집으로 폴백: python scripts/collect_web.py <url> --target <host>",
            file=sys.stderr,
        )
        return False


def parse_host_map(pairs):
    """['vhost=ip', ...] → 'MAP vhost ip,MAP vhost2 ip2' (host-resolver-rules 형식)."""
    rules = []
    mapping = {}
    for p in pairs or []:
        if "=" not in p:
            print(f"[!] --host-map 형식 오류(무시): {p} (vhost=ip 형태로)", file=sys.stderr)
            continue
        vhost, ip = p.split("=", 1)
        vhost, ip = vhost.strip(), ip.strip()
        if vhost and ip:
            rules.append(f"MAP {vhost} {ip}")
            mapping[vhost] = ip
    return (",".join(rules), mapping)


def main() -> int:
    ap = argparse.ArgumentParser(description="SPA dynamic web recon collector")
    ap.add_argument("url")
    ap.add_argument("--target", required=True, help="host label for targets/<host>/ (vhost 이름 권장)")
    ap.add_argument("--host-map", action="append", default=[],
                    help="vhost=ip (반복 가능). 같은 IP의 다른 가상호스트 수집용")
    ap.add_argument("--timeout", type=int, default=30, help="navigation timeout (s)")
    ap.add_argument("--wait", type=int, default=3, help="networkidle 후 추가 대기(s)")
    ap.add_argument("--scroll", action="store_true", help="지연 로드 청크 유발용 스크롤")
    ap.add_argument("--max-assets", type=int, default=200)
    args = ap.parse_args()

    if not _require_playwright():
        return 3
    from playwright.sync_api import sync_playwright

    tdir = os.path.join(ROOT, "targets", args.target)
    raw_dir = os.path.join(tdir, "captures", "raw")
    obs_dir = os.path.join(tdir, "captures", "observation")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(obs_dir, exist_ok=True)

    resolver_rules, host_mapping = parse_host_map(args.host_map)

    manifest = {
        "target": args.target,
        "entry_url": args.url,
        "collected_at": now_iso(),
        "collector": UA + " (spa/playwright)",
        "produced_by": os.environ.get("RECON_PRODUCED_BY", os.path.basename(__file__)),
        "collection_mode": "spa",
        "host_map": host_mapping,
        "assets": [],
    }

    launch_args = []
    if resolver_rules:
        launch_args.append(f"--host-resolver-rules={resolver_rules}")
        launch_args.append("--ignore-certificate-errors")

    seen = set()          # source_url 중복 제거
    seen_hashes = set()   # 동일 바디 중복 저장 방지
    idx = [0]
    captured = []         # (source_url, kind, status, content_type, body)

    def on_response(response):
        try:
            url = response.url
            if url in seen or len(captured) >= args.max_assets:
                return
            if url.startswith(("data:", "blob:")):
                return
            seen.add(url)
            headers = response.headers
            ctype = headers.get("content-type", "")
            try:
                body = response.body()
            except Exception:
                body = b""
            captured.append((url, kind_for(url, ctype), response.status, ctype, body))
        except Exception as e:  # noqa: BLE001
            print(f"[!] response hook error: {e}", file=sys.stderr)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=launch_args)
        context = browser.new_context(
            ignore_https_errors=True,
            user_agent=UA,
        )
        page = context.new_page()
        page.on("response", on_response)

        nav_error = None
        final_url = args.url
        rendered_dom = ""
        cookies = []
        storage = {}
        try:
            resp = page.goto(args.url, wait_until="networkidle", timeout=args.timeout * 1000)
            if args.scroll:
                try:
                    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                except Exception:
                    pass
            page.wait_for_timeout(args.wait * 1000)
            final_url = page.url
            rendered_dom = page.content()
            # React Fiber 는 DOM 노드의 expando property 로 붙기 때문에 page.content() 직렬화에
            # 안 나온다. 런타임에서 실제 property 키를 읽어 캡처한다(런타임 지문 Observation).
            fiber_keys = []
            try:
                fiber_keys = page.evaluate(
                    "() => { const found = new Set();"
                    " for (const el of document.querySelectorAll('*'))"
                    " for (const k of Object.keys(el))"
                    "  if (k.indexOf('__reactFiber$')===0 || k.indexOf('__reactContainer$')===0"
                    "   || k.indexOf('__reactProps$')===0) found.add(k);"
                    " return Array.from(found); }"
                ) or []
            except Exception:
                fiber_keys = []
            if fiber_keys:
                rendered_dom += "\n<!-- react-fiber-props: " + ", ".join(sorted(fiber_keys)) + " -->\n"
            cookies = context.cookies()
            try:
                storage = page.evaluate(
                    "() => { const o={}; for (let i=0;i<localStorage.length;i++)"
                    "{const k=localStorage.key(i); o[k]=localStorage.getItem(k);} return o; }"
                )
            except Exception:
                storage = {}
            if resp is not None:
                manifest["entry_status"] = resp.status
                # 진입 응답 헤더를 1급 매칭 자산으로 등록 (T9) — Server/X-Powered-By 등.
                try:
                    entry_headers = resp.all_headers() or {}
                    if entry_headers:
                        hb = "".join(f"{k}: {v}\n" for k, v in entry_headers.items()).encode("utf-8")
                        idx[0] += 1
                        hdr_path = os.path.join(raw_dir, f"{idx[0]:02d}___headers__.txt")
                        with open(hdr_path, "wb") as f:
                            f.write(hb)
                        manifest["assets"].append({
                            "asset_id": f"AST-{idx[0]:03d}",
                            "source_url": args.url + "#headers",
                            "asset_kind": "header",
                            "http_status": resp.status,
                            "content_type": "text/plain",
                            "raw_ref": rel(hdr_path),
                            "asset_sha256": sha256_hex(hb),
                        })
                        print(f"[+] {'header':8s} (entry response headers) -> {rel(hdr_path)}")
                except Exception as e:  # noqa: BLE001
                    print(f"[!] entry header capture failed: {e}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001
            nav_error = f"{type(e).__name__}: {e}"
            print(f"[!] navigation error: {nav_error}", file=sys.stderr)
        finally:
            context.close()
            browser.close()

    # 실패도 Observation 으로 보존 (invariants: 실패를 삭제하지 않는다)
    if nav_error:
        with open(os.path.join(obs_dir, "nav-error.txt"), "w", encoding="utf-8") as f:
            f.write(f"url: {args.url}\nerror: {nav_error}\nat: {now_iso()}\n")

    # 캡처된 네트워크 응답을 자산으로 저장
    for url, kind, status, ctype, body in captured:
        h = sha256_hex(body) if body else None
        if h and h in seen_hashes:
            continue
        if h:
            seen_hashes.add(h)
        idx[0] += 1
        name = safe_name(url, idx[0], kind)
        path = os.path.join(raw_dir, name)
        with open(path, "wb") as f:
            f.write(body)
        manifest["assets"].append({
            "asset_id": f"AST-{idx[0]:03d}",
            "source_url": url,
            "asset_kind": kind,
            "http_status": status,
            "content_type": ctype,
            "raw_ref": rel(path),
            "asset_sha256": h or "UNSET",
        })
        print(f"[+] {kind:8s} {url} -> {rel(path)}")
        # source map 수집 (T21): JS 에 sourceMappingURL 이 있으면 .map 도 자산으로
        if kind == "js":
            from collect_web import fetch as _fetch, sourcemap_url_from, urljoin as _urljoin
            sm = sourcemap_url_from(body)
            if sm:
                sm_url = _urljoin(url, sm)
                if sm_url not in seen and len(captured) < args.max_assets:
                    seen.add(sm_url)
                    sm_st, sm_hd, sm_rh, sm_body, sm_err = _fetch(sm_url, timeout=args.timeout)
                    if not sm_err and sm_body:
                        idx[0] += 1
                        sm_name = safe_name(sm_url, idx[0], "sourcemap")
                        sm_path = os.path.join(raw_dir, sm_name)
                        with open(sm_path, "wb") as f:
                            f.write(sm_body)
                        manifest["assets"].append({
                            "asset_id": f"AST-{idx[0]:03d}",
                            "source_url": sm_url,
                            "asset_kind": "sourcemap",
                            "http_status": sm_st,
                            "content_type": sm_hd.get("Content-Type", ""),
                            "raw_ref": rel(sm_path),
                            "asset_sha256": sha256_hex(sm_body),
                        })
                        print(f"[+] {'sourcemap':8s} {sm_url} -> {rel(sm_path)}")

    # 렌더된 DOM(런타임 지문 포함: __reactFiber$, data-reactroot 등)을 자산으로 저장
    if rendered_dom:
        dom_bytes = rendered_dom.encode("utf-8")
        idx[0] += 1
        dom_path = os.path.join(raw_dir, f"{idx[0]:02d}_rendered_dom.html")
        with open(dom_path, "wb") as f:
            f.write(dom_bytes)
        manifest["assets"].append({
            "asset_id": f"AST-{idx[0]:03d}",
            "source_url": final_url + "#rendered-dom",
            "asset_kind": "html",
            "http_status": manifest.get("entry_status"),
            "content_type": "text/html; charset=utf-8",
            "raw_ref": rel(dom_path),
            "asset_sha256": sha256_hex(dom_bytes),
        })
        print(f"[+] {'html':8s} (rendered DOM) -> {rel(dom_path)}")

    # 쿠키 / localStorage Observation 보존 + 쿠키 1급 매칭 자산 등록 (T9)
    # 쿠키 값 원문은 raw/(gitignore)에만 두고, 지문은 이름·플래그·형식만 사용.
    if cookies:
        with open(os.path.join(obs_dir, "cookies.json"), "w", encoding="utf-8") as f:
            json.dump(cookies, f, indent=2, ensure_ascii=False)
        lines = []
        for c in cookies:
            attrs = [f"path={c.get('path') or '/'}"]
            if c.get("httpOnly"):
                attrs.append("HttpOnly")
            if c.get("secure"):
                attrs.append("Secure")
            if c.get("sameSite"):
                attrs.append("SameSite=" + str(c["sameSite"]))
            lines.append(f"{c.get('name', '')}={c.get('value', '')}; " + "; ".join(attrs))
        ck_bytes = ("\n".join(lines) + "\n").encode("utf-8")
        idx[0] += 1
        ck_path = os.path.join(raw_dir, f"{idx[0]:02d}___cookies__.txt")
        with open(ck_path, "wb") as f:
            f.write(ck_bytes)
        manifest["assets"].append({
            "asset_id": f"AST-{idx[0]:03d}",
            "source_url": final_url + "#cookies",
            "asset_kind": "cookie",
            "http_status": manifest.get("entry_status"),
            "content_type": "text/plain",
            "raw_ref": rel(ck_path),
            "asset_sha256": sha256_hex(ck_bytes),
        })
        print(f"[+] {'cookie':8s} ({len(lines)} cookies) -> {rel(ck_path)}")
    if storage:
        with open(os.path.join(obs_dir, "localstorage.json"), "w", encoding="utf-8") as f:
            json.dump(storage, f, indent=2, ensure_ascii=False)

    mpath = os.path.join(tdir, "captures", "manifest.json")
    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    n_saved = len([a for a in manifest["assets"] if a.get("raw_ref")])
    print(f"\n[*] {n_saved} assets saved (mode=spa)")
    print(f"[*] manifest: {rel(mpath)}")
    print("[*] 다음: python scripts/normalize_js.py " + args.target
          + " && python scripts/fingerprint.py " + args.target)
    return 0 if not nav_error else 2


if __name__ == "__main__":
    raise SystemExit(main())
