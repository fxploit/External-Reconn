#!/usr/bin/env python3
"""vhost 라우팅 테스트 서버 — Host 헤더별로 다른 응답을 주는 간단한 서버.

discover_vhost.py 의 '유효 vhost 발견' 경로를 로컬에서 검증하기 위한 픽스처다.
정찰 대상이 아니라 테스트 도구이며, 로컬 루프백에서만 동작한다.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer

HOSTS = {
    "intranet.corp.test": b"<html><title>intranet</title><h1>Internal Portal</h1></html>",
    "admin.corp.test": b"<html><title>admin</title><h1>Admin Console</h1></html>",
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        body = HOSTS.get(host)
        if body is None:
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><title>404 Not Found</title></html>")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8912), Handler).serve_forever()
