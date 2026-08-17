/* fixture — 가짜 시크릿/엔드포인트/에러 (테스트 전용, 실제 키 아님) */
(function () {
  var AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
  var aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
  var github_token = "ghp_0123456789abcdef0123456789abcdef0123";
  var google_key = "AIzaSyA0123456789abcdefghijklmnopqrstuv";
  fetch("https://api.example.com/v1/users?limit=10");
  fetch("/api/admin/config");
  fetch("/graphql");
  try {
    throw new Error("boom");
  } catch (e) {
    console.error("Traceback (most recent call last):\n  File \"app.py\", line 10, in main\nRuntimeError: demo");
  }
  /* nginx/1.18.0 */
})();
