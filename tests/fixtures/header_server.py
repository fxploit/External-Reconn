#!/usr/bin/env python3
"""헤더/본문 지문 픽스처 서버 — nginx/Apache/PHP 헤더 + 프레임워크 마커 본문.

T6(시그니처 DB)의 결정론 매칭을 로컬에서 검증하기 위한 픽스처다. 정찰 대상이 아니라
테스트 도구이며, 로컬 루프백에서만 동작한다.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer

BODY = b"""<!DOCTYPE html>
<html>
<head>
  <title>Fixture Multi-Product</title>
  <meta name="generator" content="WordPress 6.4.2">
  <meta name="csrf-token" content="abc123">
  <script>window.__NEXT_DATA__ = {"buildId":"fxb9a2","props":{}};</script>
  <script>var Vue = { version: "3.4.21" }; createApp({}).mount("#app");</script>
  <script src="/wp-content/themes/twentytwenty/assets/app.js"></script>
</head>
<body>
  <div id="app" data-v-7a1b2c3d></div>
  <div ng-app="myApp" ng-controller="MainCtrl"></div>
  <a href="/wp-login.php">Login</a>
  <a href="/index.php?id=1">Post</a>
  <footer>Welcome to nginx! Powered by Laravel</footer>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "nginx/1.18.0 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/7.4.33")
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8913), Handler).serve_forever()
