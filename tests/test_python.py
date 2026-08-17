#!/usr/bin/env python3
"""파이썬 유닛 테스트 — normalize_js / fingerprint 의 결정론 함수 회귀 방지.

pytest 없이 실행: `python tests/test_python.py` (실패 시 exit 1)
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import normalize_js  # noqa: E402
import fingerprint  # noqa: E402
sys.path.insert(0, os.path.join(ROOT, "scripts", "lib"))
import self_repair  # noqa: E402

PASS = 0


def check(name, cond, detail=""):
    global PASS
    if not cond:
        print(f"FAIL: {name} {detail}", file=sys.stderr)
        raise SystemExit(1)
    PASS += 1
    print(f"  ok {name}")


# ── normalize_js: 패커 언패킹 ────────────────────────────────────────────────
PACKED = ('eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!\'\'.replace(/^/,String))'
          '{while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return\'\\\\w+\'};'
          'c=1};while(c--)if(k[c])p=p.replace(new RegExp(\'\\\\b\'+e(c)+\'\\\\b\',\'g\'),k[c]);'
          'return p}(\'0\',2,1,\'HelloWorld\'.split(\'|\'),0,{}))')

unpacked, ok = normalize_js.unpack_packed(PACKED)
check("unpack_packed 성공", ok)
check("unpack_packed 결과에 심볼 포함", "HelloWorld" in unpacked)

# 비패커 입력은 그대로
src = "var a = 1;"
un, ok2 = normalize_js.unpack_packed(src)
check("비패커 입력 불변", not ok2 and un == src)

# ── normalize_js: 인코딩 디코딩 ──────────────────────────────────────────────
kr = "한글 테스트".encode("cp949")
check("decode_bytes CP949", normalize_js.decode_bytes(kr) == "한글 테스트")
bom = b"\xef\xbb\xbf" + "hi".encode("utf-8")
check("decode_bytes UTF-8 BOM", normalize_js.decode_bytes(bom) == "hi")

# ── fingerprint: 시그니처 매칭 ───────────────────────────────────────────────
sig = {"match": {"type": "regex", "pattern":
                 "jQuery\\s+JavaScript\\s+Library\\s+v?(?P<version>[0-9]+\\.[0-9]+\\.[0-9]+)"}}
res = fingerprint.match_signature(sig, "/* jQuery JavaScript Library v3.6.0 */")
check("시그니처 정확 버전 캡처", res and res["version"] == "3.6.0")

res2 = fingerprint.match_signature({"match": {"type": "literal", "pattern": "createRoot("}},
                                   "ReactDOM.createRoot(document)")
check("리터럴 매칭", res2 and res2["quote"] == "createRoot(")

# ── fingerprint: 근거 바인딩 (quote 바이트가 실제 파일에 존재해야 함) ─────────
with tempfile.TemporaryDirectory() as d:
    raw_path = os.path.join(d, "a.js")
    with open(raw_path, "wb") as f:
        f.write("/* jQuery JavaScript Library v3.6.0 */".encode("utf-8"))
    raw_triple = (raw_path, "/* jQuery JavaScript Library v3.6.0 */",
                  open(raw_path, "rb").read())
    bound = fingerprint.bind_evidence("jQuery JavaScript Library v3.6.0", raw_triple, None)
    check("bind_evidence 유효 인용 바인딩", bound is not None)
    bound2 = fingerprint.bind_evidence("FakeLib 9.9.9", raw_triple, None)
    check("bind_evidence 없는 인용은 None", bound2 is None)

# ── fingerprint: 인코딩 견고한 decode ────────────────────────────────────────
check("fingerprint decode_bytes CP949", fingerprint.decode_bytes(kr) == "한글 테스트")

# ── T20: 자가개선 가드레일 ─────────────────────────────────────────────────────
import shutil  # noqa: E402

# (1) 허용 대상 사본 생성 → 원본 불변, 사본 존재
src_collect = os.path.join(ROOT, "scripts", "collect_web.py")
variant = self_repair.make_variant(src_collect, "guard-test")
check("make_variant 사본 생성", os.path.exists(variant) and variant != src_collect)
check("make_variant 원본 불변", os.path.exists(src_collect))
check("make_variant 사본 위치", os.path.dirname(variant) == self_repair.VARIANTS_DIR)
os.remove(variant)  # 정리

# (2) 신뢰 앵커 자가수정 시도 → 차단(PermissionError)
try:
    self_repair.make_variant(os.path.join(ROOT, "scripts", "check-recon.mjs"), "guard-test")
    check("신뢰 앵커 차단", False, "check-recon.mjs 자가수정이 허용되면 안 됨")
except PermissionError as e:
    check("신뢰 앵커 차단", "신뢰 앵커" in str(e))
try:
    self_repair.make_variant(os.path.join(ROOT, "harness", "policies", "invariants.md"), "guard-test")
    check("신뢰 앵커 차단(invariants)", False)
except PermissionError:
    check("신뢰 앵커 차단(invariants)", True)

# (3) 허용 대상 외 파일 → 차단
try:
    self_repair.make_variant(os.path.join(ROOT, "scripts", "fingerprint.py"), "guard-test")
    check("허용 외 파일 차단", False, "fingerprint.py 는 자가개선 허용 대상 아님")
except PermissionError as e:
    check("허용 외 파일 차단", "허용 대상 아님" in str(e))

# (4) 자가개선 로그 append
log_path = self_repair.log_entry("guard-test", {
    "source": "collect_web.py", "variant": variant,
    "symptom": "테스트 증상", "hypothesis": "테스트 가설",
    "change_summary": "테스트", "npm_test": "pass", "gate": "GO", "verdict": "채택",
})
check("로그 md 생성", os.path.exists(log_path))
check("로그 json 생성", os.path.exists(os.path.join(ROOT, "targets", "guard-test", "self-repair-log.json")))
shutil.rmtree(os.path.join(ROOT, "targets", "guard-test"), ignore_errors=True)

print(f"\n[test_python] {PASS} passed")
