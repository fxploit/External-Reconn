#!/usr/bin/env python3
"""Flask/Django 스타일 픽스처 서버 — 헤더·쿠키·본문 지문 검증용.

T9(헤더·쿠키 1급 자산)과 T10(Flask/Django 시그니처)의 결정론 매칭을 로컬에서 검증한다.
정찰 대상이 아니라 테스트 도구이며, 로컬 루프백에서만 동작한다.
- Server: Werkzeug/3.0.1 Python/3.12.3  (Flask 계열 — Werkzeug 버전 confirmed)
- Set-Cookie: Flask 서명 세션(session=eyJ…sig), Django csrftoken, sessionid
- 본문: Django admin 마커, Werkzeug 디버거 마커, 버전 문자열
"""
from http.server import BaseHTTPRequestHandler, HTTPServer

BODY = b"""<!DOCTYPE html>
<html>
<head><title>Fixture App</title></head>
<body>
  <form action="/admin/login/" method="post">
    <label>Username</label><input name="username" type="text">
    <label>Password</label><input name="password" type="password">
    <input type="submit" value="Log in">
  </form>
  <pre>Werkzeug Debugger</pre>
  <code>RuntimeError: something went wrong</code>
  <link rel="stylesheet" href="/static/admin/css/base.css">
  <script>
    var apiKey = "AKIAIOSFODNN7EXAMPLE";
    var ghToken = "ghp_0123456789abcdef0123456789abcdef0123";
    var endpoint = "https://api.internal.example/v1/deploy?key=abc";
  </script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Werkzeug/3.0.1 Python/3.12.3")
        # Flask itsdangerous 서명 세션 쿠키 형식 (base64url JSON . 서명)
        self.send_header("Set-Cookie", "session=eyJsb2dnZWRfaW4iOnRydWV9.Zm9v.Zm9vLXNpZ24tZXhhbXBsZQ; HttpOnly; Path=/")
        # Django 쿠키
        self.send_header("Set-Cookie", "csrftoken=abcdef1234567890; Path=/; SameSite=Lax")
        self.send_header("Set-Cookie", "sessionid=zzz9u8t7s6; HttpOnly; Path=/")
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8914), Handler).serve_forever()
