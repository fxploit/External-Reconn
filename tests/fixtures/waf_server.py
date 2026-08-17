#!/usr/bin/env python3
"""WAF 시뮬레이션 픽스처 서버 — 능동 방어 프로브(T22) 검증용.

깨끗한 요청은 200, 의심 페이로드(x= 파라미터에 <script>/../ 등)에는 403 차단 페이지를 준다.
정찰 대상이 아니라 테스트 도구이며, 로컬 루프백에서만 동작한다.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs

SUSPICIOUS = ("<script", "..%2f", "..%2F", "../", "etc/passwd", "' or '", "%27%20or%20")
BLOCK_PAGE = b"""<html><head><title>Attention Required! | Cloudflare</title></head>
<body><h1>Attention Required!</h1><p>You have been blocked.</p></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        qs = parse_qs(urlsplit(self.path).query)
        x = (qs.get("x") or [""])[0].lower()
        if any(s in x for s in SUSPICIOUS):
            self.send_response(403)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("cf-ray", "8a1b2c3d4e5f-ICN")
            self.end_headers()
            self.wfile.write(BLOCK_PAGE)
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8915), Handler).serve_forever()
