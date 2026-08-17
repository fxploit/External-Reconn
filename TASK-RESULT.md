# TASK-RESULT.md — TASK.md 수행 결과 기록

> TASK.md(Recon Harness 구현 지시서)의 각 태스크를 어떻게 수행했는지, 무엇을 만들었고
> 어떻게 **게이트로 검증**했는지를 기록한다. 완료 기준은 "코드가 돌아간다"가 아니라
> "`npm run check -- <target>` 이 의도한 결과(GO/REVISE/STOP)를 낸다"였다.

---

## 0. 시작 전 상태

- 이미 동작하던 것: 정적/SPA 수집, 정규화, 결정론 핑거프린트(React/jQuery), 게이트, vhost 수집.
- 미구현(계약만): AI fallback 추론, 2차 재검증, vhost 발견·능동 정찰 러너, Docker 환경, 시그니처 확장, 테스트.
- 환경: Windows + Docker Desktop 29.5, Python 3.12, Node 24. `npm test`는 없었다.

---

## T1. Docker 실행 환경 (완료)

**만든 것**
- `docker/Dockerfile` — 베이스 `mcr.microsoft.com/playwright/python:v1.53.0-noble` 을
  `@sha256:648e2d7c…` 로 고정. nmap·gobuster·curl·dnsutils + playwright==1.53.0(베이스에 깔린
  chromium-1179 빌드와 버전을 맞춰 재다운로드 방지)·jsbeautifier 설치. scripts/harness/package.json 복사.
- `docker/compose.yaml` — **장수(long-lived) 컨테이너** 모델(`command: sleep infinity` +
  `docker exec`). `targets/`를 `/work/targets`로 마운트, scope.md 는 읽기 전용 마운트. 이미지를
  `recon-harness@sha256:71044ff…` 로 고정. 네트워크 접근(VPN 등)은 미정이라 접근 프로파일을 주석으로 비워둠.
- `scripts/recon.mjs` — `docker compose up -d`(미가동 시) 후 `docker exec` 로 명령을 투입하는 얇은 래퍼.
  실행 후 **실행 중 컨테이너의 `.Image`(이미지 ID sha256)** 를 읽어 `runtime_image_digest` 로
  manifest 에 기록(태그 재조회 금지). Docker 미사용 시 호스트 직접 실행 폴백.

**검증**
- 컨테이너에서 `collect_web.py`/`collect_spa.py` 실행 → `targets/<host>/` 에 원본·manifest 생성.
- manifest 에 `runtime_image_digest=sha256:71044ff…` 기록 확인.
- 호스트에서 `npm run check -- <target>` **GO**.
- 진행 중 발견: 베이스 이미지에 브라우저만 있고 playwright pip 패키지가 없어 Dockerfile 에 추가 설치.
  재빌드마다 digest 가 바뀌어 compose 를 갱신(총 3회, 최종 `71044ff…`).

> 참고: 로컬/컨테이너 검증용으로 `scope.md` 에 `127.0.0.1/8`(로컬 테스트 대역, 주석으로 임시 명시)을
> 추가했다. **CTF 당일 실제 할당 대역으로 반드시 교체 필요.**

---

## T2. AI fallback 추론 (완료)

**만든 것**
- `harness/prompts/fallback-inference.md` — 서브에이전트 작업 계약.
  제품/버전은 **자산에서 바이트 그대로 인용 가능할 때만** 제시, `provenance ∈ {inferred, guess, unknown}`,
  `confirmed` 금지, `unknown`이 정답이라는 규칙 명시.
- `scripts/merge_fallback.py` — 판정 JSON 을 받아 병합:
  - `inferred`/`guess` → 기존 `unknown` 발견을 **업그레이드**(아니면 신규 추가), `unmatched`에서 제거.
  - `unknown` → `unmatched`에 그대로 보존(삭제 금지).
  - **병합 전에** `evidence_quote`의 UTF-8 바이트가 evidence 파일에 존재하는지 검증 → 지어낸 인용은
    "fabricated"로 거부. `confirmed` 판정은 계약 위반으로 거부. 중복 판정 가드.

**검증**
- 유효 인용 → 병합 후 게이트 **GO**.
- 지어낸 인용 → 병합 단계에서 `evidence_quote not found in asset — fabricated` 거부.
  (게이트 안전망은 T8 테스트에서 별도 증명: findings 에 직접 주입하면 게이트가 REVISE.)
- `unknown` 판정 → `unmatched` 유지 확인.
- Windows 콘솔(CP949)에서 한글/특수문자 출력 크래시를 막는 `_utf8_stdio()` 추가.

---

## T3. 2차 재검증 러너 (완료)

**만든 것**
- `harness/prompts/second-pass-verify.md` — **맥락 제거** 재판정 계약(증거 인용 + 원문 일부만 제공).
- `scripts/second_pass.py` — `--prepare`(confirmed 대상의 증거만 뽑아 입력 생성) /
  `--apply`(판정 적용):
  - `support` → `verified_by += second-pass:support`, provenance 유지.
  - `contradict` → `verified_by += second-pass:contradict`, **confirmed → inferred 강등**.
  - `unknown` → 등급 불변(보수적).
- 게이트 `lib/checks.mjs` 의 confirmed 인정 정규식을 `fingerprint.py:*/active_recon.py:*/discover_vhost.py:*`
  또는 `second-pass` 로 확장(결정론적 도구 출력을 confirmed 근거로 인정).

**검증**
- support → confirmed 유지 + 게이트 GO. contradict → 강등 반영(integration 테스트로 고정).

---

## T4. vhost 발견 러너 (완료, 능동)

**만든 것**
- `scripts/discover_vhost.py` — Host 헤더 워드리스트 브루트. **무작위 vhost 기준선(baseline)** 과
  상태코드/본문크기/본문해시를 비교해 유효 vhost 판별(와일드카드 오탐 억제). 결과는 Observation 보존.
- **GO 게이트**: `--recon-id` + `--approved` 둘 다 없으면 요청을 한 건도 보내지 않고 exit 3.

**검증**
- 승인 없이 실행 → `[STOP]` (exit 3, 요청 0건).
- 로컬 vhost 라우팅 픽스처(`tests/fixtures/vhost_server.py`)로: `intranet.corp.test`/`admin.corp.test`
  발견, 오탐(`api/mail`)은 baseline 대조로 미발견.
- 발견된 vhost 를 `collect_spa.py --host-map` 으로 재수집 → 타깃 게이트 **GO**.

---

## T5. 능동 정찰 러너 (완료, 능동)

**만든 것**
- `scripts/active_recon.py` — nmap(`-sV`) 포트/서비스 스캔 + gobuster/순수 파이썬 폴백 디렉터리 열거.
  실행마다 명령·stdout/stderr·exit code·타임스탬프를 `captures/observation/*-<recon_id>.txt/.json` 보존.
  - nmap 서비스 라인 → `confirmed` 발견으로 findings 반영(근거는 **실제 도구 출력 파일**에 바인딩).
  - 디렉터리 200/3xx/401 → `inferred` 발견.
- **GO 게이트**(`--recon-id`+`--approved`)와 **스코프 게이트**(scope.md 대역 밖 IP면 요청 전 STOP).

**검증**
- 승인 없음 → STOP. 대역 밖 IP(`192.168.99.99`) → STOP.
- 컨테이너에서 `nmap -sV -p 8000` 실행 → `SimpleHTTPServer 0.6 (Python 3.12.3)` 배너를
  `confirmed` 발견으로 반영 → 게이트 **GO**.

---

## T6. 시그니처 DB 확장 (완료)

**만든 것** (모두 `harness/signatures/` JSON 데이터 — 스크립트 로직 아님)
- Angular(배너/ngVersion/module/ng-app/zone.js), Vue(배너/Vue.version/createApp/new Vue/data-v-),
  Next.js(__NEXT_DATA__/chunks/buildId), WordPress(wp-content/generator 메타 버전/wp-login),
  nginx·Apache·PHP(**응답 헤더** 기반 + 기본 페이지), Laravel(csrf-token/브랜딩).

**부가 확장**
- nginx/Apache/PHP 지문은 HTTP 응답 헤더에만 있는데 기존 자산엔 헤더가 없어,
  `fingerprint.py` 가 `captures/observation/entry-headers.json` 을 탐색 표면에 추가하는
  `match_headers()` 를 추가(규칙은 여전히 JSON 데이터, `asset_kinds: ["header"]`).

**검증**
- 헤더+본문 픽스처 서버(`tests/fixtures/header_server.py`)로 확인:
  nginx 1.18.0 / PHP 7.4.33(헤더 confirmed), WordPress 6.4.2(generator 메타 confirmed),
  Next.js/Vue3/AngularJS inferred → 게이트 **GO**.

---

## T7. 라이브 SPA 검증 + 의존성 정리 (완료)

**한 것**
- `requirements.txt` 작성(playwright==1.53.0, jsbeautifier==2.0.3) + 로컬 설치 검증.
- 실제 React 18.2.0 SPA 픽스처(UMD 빌드)로 collect_spa → normalize → fingerprint → gate 전 구간 실행 → **GO**.
- 발견: `page.content()` 직렬화에는 React Fiber 지문(`__reactFiber$`)이 JS expando 라 안 나온다.
  → `collect_spa.py` 가 **런타임에서 fiber property 키를 읽어** 렌더 DOM 에 기록하도록 개선.
  확인: `react-fiber-props: __reactContainer$…, __reactFiber$…, __reactProps$…` 가 DOM 자산에 캡처되고
  시그니처로 매칭됨.

---

## T8. 테스트 · 회귀 방지 (완료)

**만든 것**
- `tests/gate.test.mjs` — 정상 GO / 해시 조작 REVISE / 인용 조작(fabricated) REVISE / 대역 밖 STOP /
  CP949 자산 GO / confirmed 자가 승격 REVISE / unknown 명시 발견 규칙.
- `tests/integration.test.mjs` — 실제 스크립트 end-to-end: fingerprint→gate, CP949 파이프라인,
  **fabricated 인용 게이트 REVISE**(안전망 증명), second_pass support/contradict, merge_fallback 병합·보존·거부,
  T9(헤더/쿠키 매칭), T11(Django 해시), T15(시크릿 마스킹).
- `tests/test_python.py` — normalize 패커 언패킹, 인코딩 디코딩(CP949/BOM), 시그니처 캡처, bind_evidence.
- `package.json` 에 `"test": "node --test \"tests/*.test.mjs\" && python tests/test_python.py"`.

**검증**
- `npm test` → **node 15개 + python 10개 전부 통과**.
- CP949 바이트는 파이썬으로 미리 계산해 hex 로 고정(Node 는 `cp949` 인코딩 미지원).

---

# Phase 2 (T9~T17) 수행 결과

## T9. 헤더·쿠키 1급 매칭 자산 (완료)

- `collect_web.py` — `fetch()` 가 원본 헤더 리스트(다중 Set-Cookie 보존)를 반환하도록 확장,
  진입 응답을 `captures/raw/__headers__.txt`(header)·`__cookies__.txt`(cookie) 자산으로 등록.
- `collect_spa.py` — 진입 응답 헤더(`resp.all_headers()`)와 브라우저 쿠키(`context.cookies()`)를
  동일하게 raw 자산으로 등록. **쿠키 값 원문은 raw/(gitignore)에만, 지문은 이름·플래그·형식만.**
- `fingerprint.py` — 기존 `match_headers()`(observation JSON 전용 bespoke) **흡수·폐기**, 일반 자산
  루프가 header/cookie kind 를 처리. nginx/Apache/PHP 헤더 시그니처를 JSON 형식 → `Name: Value`
  텍스트 형식으로 재작성. 정규식 컴파일에 MULTILINE 추가(다중 라인 자산의 `^` 앵커).
- 검증: 정적·SPA 양쪽에서 헤더/쿠키 자산이 잡히고, nginx 1.18.0 / PHP 7.4.33 header confirmed,
  Django 쿠키(csrftoken/sessionid) inferred → 게이트 GO. 회귀 테스트 추가.

## T10. Flask/Django 시그니처 (완료)

- `flask.json` — session 쿠키(itsdangerous 형식, **lookahead 로 값 원문 미인용**), Werkzeug 디버거 마커.
- `django.json` — csrftoken/sessionid 쿠키, admin 로그인 폼, /static/admin/, DEBUG 에러페이지.
- `werkzeug.json` — Server 헤더 Werkzeug 버전 confirmed.
- **설계 판단**: Werkzeug 버전을 product=Flask 로 두면 (Flask, 3.0.1) 오인으로 다운스트림 CVE
  하네스가 Flask 3.0.1 로 잘못 자동 진행할 수 있어, Werkzeug 를 별도 제품으로 분리(T11 매핑으로 Flask 범위).

## T11. 버전 범위/해시 DB (완료)

- `harness/signatures/maps/werkzeug-flask.json` — Werkzeug 버전 → Flask 릴리스 시기(범위, inferred).
  fingerprint 의 `apply_werkzeug_flask_map()`: confirmed Werkzeug → Flask version_bound.
- `harness/signatures/maps/django-static-hashes.json` — **Django 공식 PyPI 릴리스 휠에서 추출한**
  admin 정적 자산 sha256 → 버전(추측 아님, 출처 문서화). `scripts/build_django_hash_db.py` 가 재구축.
  fingerprint 의 `apply_django_hash_db()`: 해시 일치 → confirmed(버전 1개) 또는 버전 범위(해시 공유 시).
  해시로 결정된 자산의 모순적 `unknown` 발견은 제거.
- 검증: base.css sha256 → Django 4.2.11 confirmed, Werkzeug 3.0.1 → Flask >=3.0 inferred, 게이트 GO.

## T12. 서버사이드 능동 프로브 (완료, 능동)

- `active_recon.py --server-probe` — 제품 힌트(findings) 기반 프로브(robots.txt, 404, Django
  admin login/base.css, wp-login/wp-json). 응답을 **raw 자산으로 저장·manifest 등록** 후
  fingerprint 를 재실행 → 시그니처/해시 DB 가 그대로 적용. 결과는 Observation 보존.

## T13. 운영 보강 (완료)

- `wordlists/` 신설 + compose 에 `/work/wordlists:ro` 마운트(컨테이너의 gobuster 기본 경로 부재 문서화).
- nmap 배너 파싱 정밀화: `parse_banner()` 로 product/version 토큰 분리, 버전 미상이면 inferred.
- discover_vhost https(SNI) 한계 경고.
- README 에 merge_fallback exit 1 의미·세션 Cleanup(잔여 it-<ts> 타깃)·AWS 공인 접근 허용 문서화.

## T14. AWS 인프라 정찰 (완료, 우선순위 3)

- `aws_recon.py` — S3 버킷 공개 리스팅 확인(`--approved-for-public` 필수, 공인 접근 scope 예외) +
  메타데이터(169.254.169.254) **접근 신호만 기록**(취득은 익스플로잇 하네스 위임).

## T15. 자산 추출 (시크릿·엔드포인트·에러버전) (완료)

- `extract_assets.py` — 결정론 regex 패스 + `--cariddi`(컨테이너 cariddi 통합).
  - **존재=confirmed / 해석=inferred 분리**. 시크릿 원문은 observation(gitignore)에만, findings 는
    형식 프리픽스(AKIA/ghp_ 등 비밀 아님) 인용 + `secret_masked`(앞4자+길이).
  - cariddi v1.4.6 바이너리를 Dockerfile 에 checksum 검증으로 고정.
- 검증: 가짜 키/엔드포인트/에러 검출, 마스킹 확인, 게이트 GO.

## T16. 스코프 제한 크롤 (완료)

- `collect_web.py --depth N`(기본 1, 상한 3) — 동일 netloc 내부만 따라가고 외부 도메인은
  `observation/external-links.txt` 에 기록만(미크롤). 해시 중복 저장 방지.
- 검증: depth 2 로 내부 페이지(page2/page3) 수집, 외부 링크 미크롤, 게이트 GO.

## T17. 서브도메인·DNS 발견 (완료)

- `discover_dns.py` — `--passive`(자산에서 base 도메인 호스트 문자열 추출, 존재 confirmed) +
  `--active`(워드리스트 DNS 브루트, **GO+approved+스코프 게이트**, 해석 IP 가 대역 밖이면 기록만).

---

# Phase 3 (T18~T20) 수행 결과

## T18. fingerprint 멱등 병합 — 데이터 유실 방지 (완료, 우선순위 0)
- **결함 확인**: fingerprint 가 findings.json 을 통째로 덮어써서 `active_recon --server-probe` 가
  fingerprint 를 재실행할 때 방금 append 한 nmap 발견이 자기파괴되고, merge_fallback/second_pass 결과도
  소실됨.
- **구현**: `fingerprint.py` 에 `load_existing()` + `merge_idempotent()` + `_is_foreign()` 추가.
  - 모든 fingerprint 산출 발견에 `generated_by: "fingerprint.py"` 부여.
  - 외부 출처(active_recon/extract_assets/discover_*/fallback-inference/second-pass/cariddi/aws_recon)
    는 **보존**, fingerprint 소유만 교체.
  - 보존 발견이 있는 자산(evidence_path)은 unknown/unmatched 재생성을 건너뜀.
  - (evidence_path, product) 가 보존 발견과 같으면 신규 signature 발견도 재생성하지 않음
    (second-pass 판정 보호).
- **회귀 테스트**: nmap 발견 append → fingerprint 재실행 후 잔존 / second-pass contradict 강등이
  재실행에도 유지 / fallback 업그레이드 보존 + unknown 미재생성. 게이트 GO.

## T19. 검토 발견 결함 수정 (완료)

- **#3 vhost FQDN**: `discover_vhost.py --domain <base>` — bare label 을 `word.base` 로 확장(이미 점이
  있으면 그대로). 재수집 안내도 FQDN.
- **#4 dir 발견 스키마**: `active_recon.py` 디렉터리 발견을 `asset_kind: "path"` + `product/version=UNSET`
  + `http_status` 필드로 정리 — CVE 하네스가 (product, version) 조회 시 오염되지 않게.
- **#5 scope 주석 방어**: 게이트(checks.mjs)와 `active_recon`/`discover_vhost`/`discover_dns` 의
  scope 파서가 `<!-- ... -->` 를 **먼저 제거** 후 `허용 대역:` 을 찾도록 수정. 활성 라인 삭제 시
  주석 예시 대역이 조용히 활성화되는 것 방지. discover_vhost 에 스코프 게이트도 추가.

## T20. 자가개선(self-repair) 메커니즘 + 로그 (완료)

- `scripts/lib/self_repair.py` — 정책을 코드로 강제:
  - `new-variant`: `scripts/variants/<원본>.<target>.<ts>` 사본 생성(원본 불변). **신뢰 앵커
    (check-recon.mjs/checks.mjs/AGENTS.md/invariants.md)는 차단(exit 3)**, 허용 대상(수집기·도구 래퍼·
    정규화) 외도 차단.
  - `log`: `targets/<host>/self-repair-log.md`(+.json) 표준 형식 append(실패 시도 보존).
  - `verify`: npm test + `npm run check -- <target>` 채택 게이트.
- `produced_by` 필드: 수집기 manifest·fingerprint findings 가 `RECON_PRODUCED_BY`(변형본 경로)를 기록.
- 검증: 유닛 테스트(사본 생성·원본 불변·가드레일 차단·로그), 컨테이너 가드레일 차단 확인.

---

# Phase 4 (T21) 수행 결과

## T21. 난독화 JS 심층 해석 — 숨은 정보 수집 (완료)

**만든 것**
- `scripts/deobfuscate.py` — 유형 탐지 → 매칭 디코더 라우팅:
  - **eval-packer**(p,a,c,k,e,d): normalize 의 언패커 재사용(기존 커버와 동일).
  - **string-array**(javascript-obfuscator 단순형): `var _0x.. = ['..']` 배열 + `function _0x..(x){return _0x..[x-offset]}` 형태
    휴리스틱 언패커. **rotate("crazy": push/splice/shift 로 배열을 섞는 변형)는 미지원 → unknown 보존**(억지 복원 금지).
  - **범용 인코딩 블롭**: JS 문자열 리터럴의 base64/hex/URL-encoded 를 **재귀 디코딩**(깊이 상한 3) +
    **가역성 체크**(re-encode 대조)로 오디코드 억제. 비가독 결과(바이너리)는 폐기.
  - **source map 복원**: `//# sourceMappingURL=` → `.map` 자산 → `sourcesContent` 원본 소스 복원(가장 깨끗한 경로).
- 수집기(`collect_web`/`collect_spa`): JS 응답에서 sourceMappingURL 을 발견하면 `.map` 을 fetch 해
  `asset_kind: "sourcemap"` 자산으로 등록.
- **디코드본 재분석**: 산출물을 `captures/decoded/` 에 표준 UTF-8 저장·해시하고 manifest 에 등록
  (`derived_from` = 원본 asset_id, `decoder` = 사용 디코더), 이후 normalize/fingerprint/extract 재적용.
- **환각 통제**: 디코드본은 파생물로 표기(derived_from/decoder), finding 근거는 디코드 파일(실재)에 바인딩,
  asset_sha256 은 디코드 파일에서 재계산(게이트 일치). 가역성 체크로 오디코드 억제, 시크릿은 기존 마스킹.

**검증** (tests/fixtures/obfuscated/)
- eval-packer → `/api/hidden/config`, `hidden-framework 4.7.1` 발견.
- string-array → `/api/admin/storage`, `Bearer `, `storage-app 2.3.1` 발견.
- base64/hex 블롭 → `https://hidden.example.com/api/secret`, `https://api.hidden.com/v1/users`, `1.2.3` 발견
  (비가독 base64 는 미검출).
- source map → `src/app.ts`/`src/config.ts` 원본 복원 → `/api/healthz`, `https://admin.internal.example/storage` 발견.
- 게이트 GO. 회귀 테스트 추가(숨은 엔드포인트 5종 확인 + derived_from/decoder 기록).

**경계**: VM 기반·완전 커스텀 난독화는 복원 시도 안 함(무한). 못 뚫으면 unknown 보존.

---

# Phase 5 (T22) 수행 결과

## T22. WAF/CDN/IPS/레이트리밋 방어 태세 탐지 (완료)

**만든 것**
- `harness/signatures/waf.json`·`cdn.json` — **데이터만**(스크립트 로직 없음). T9 의 헤더/쿠키 자산을 재사용:
  Cloudflare(`cf-ray`/`__cf_bm`/`cf_clearance`/챌린지페이지), Akamai(`X-Akamai-*`/`_abck`/`ak_bmsc`),
  Imperva(`X-Iinfo`/`incap_ses_*`/`visid_incap_*`), F5 BIG-IP(`BIGipServer`/`TS*`), ModSecurity(`Mod_Security`/`NOYB`),
  Sucuri(`X-Sucuri-ID/Cache`), AWS WAF, FortiWeb(`FORTIWAFSID`), Wordfence(`wfvt_`), Barracuda, CDN(Cloudflare/Fastly/CloudFront/Akamai).
  고유 마커 존재 = `confirmed`(바이트 인용). 복수 탐지 허용.
- `scripts/waf_recon.py` — 능동 방어 프로브(**GO+approved+스코프 게이트**):
  - `--wafw00f`: wafw00f 2.4.2(이미지 고정) 실행 → JSON(`firewall`/`detected`) 파싱 → WAF `confirmed`.
  - `--payloads`: 무해한 엔드포인트에 소량 벤치 페이로드 → 차단 반응(403/406/418/429/501/503) 관찰 → WAF/IPS `inferred`.
    **트립(차단 관찰) 시 즉시 중단·사람 보고.**
  - `--rate N`: 연속 요청 후 429/드롭 → `ratelimit` `inferred`.
- **결과 클래스 분리**: transport 실패(RST/timeout)와 정상 403/404, WAF 차단 페이지를 별도 기록.
- **정직한 경계**: 순수 패시브 IDS 는 대개 탐지 불가 → `unknown` 보존(지어내지 않음).
- 산출: `asset_kind: "defense"`, product = `waf`/`cdn`/`ratelimit`. 다운스트림에 "스캔 강도 조절" 입력.

**검증** (tests/fixtures/)
- 패시브: cf-ray + Server: cloudflare + __cf_bm/wfvt_ 픽스처 → Cloudflare/Wordfence/Sucuri/CDN `confirmed`, 게이트 GO.
- GO 게이트: `--approved` 없이 waf_recon → **STOP(exit 3)**.
- 능동: WAF 시뮬레이션 서버(tests/fixtures/waf_server.py)에서 페이로드 → 403 차단 → `inferred` 발견, 게이트 GO.
- IDS 는 미탐(unknown) 유지. 회귀 테스트 2건 추가. `npm test` node 20 + py 18 통과.

**환각 통제**: 고유 마커=confirmed / 행위 추론=inferred / IDS 미탐=unknown. 프로브 응답을 evidence 파일로 바인딩
(observation 먼저 저장 후 sha/인용 계산). 능동 프로브는 GO 게이트.

---

## 기존 구성의 수정 (의도·근거)

| 항목 | 변경 | 이유 |
|---|---|---|
| `scope.md` | `127.0.0.1/8` 임시 추가(주석에 교체 요구 명시) | 로컬 검증으로 게이트 GO 확인. 사람 승인 후 진행 |
| `lib/checks.mjs` | confirmed 인정 정규식 확장 | nmap 등 결정론 도구 원본 출력을 confirmed 근거로 인정(불변조건 "결정론적 도구 매칭"의 정상화) — extract_assets/discover_dns/aws_recon 추가 |
| `fingerprint.py` | 미매칭 자산 → **명시적 `unknown` 발견** + header/cookie kind + MULTILINE + 매핑/해시 DB 패스 | unknown 1급 출력화 + T9/T11 substrate. **해시는 evidence 파일 기준으로 재계산**(기록.md 5절 버그 재발 방지) |
| `merge_fallback.py` | 기존 unknown 발견 **업그레이드** 방식 | findings = 자산당 1건 모델 유지, 중복 발견 방지 |
| `collect_spa.py` | 런타임 fiber 지문 캡처 + 진입 헤더/쿠키 자산 | page.content() 직렬화 한계 보완 + T9 |
| `collect_web.py` | `fetch()` 원본 헤더 반환 + depth 크롤 | T9 substrate + T16 |
| `docker/Dockerfile` | cariddi(checksum 고정), unzip 추가 | T15 |
| `docker/compose.yaml` | scope.md + wordlists 읽기 전용 마운트, digest 갱신(최종 `6e4554b7…`) | 컨테이너가 최신 대역/워드리스트를 읽도록 |
| nginx/apache/php 시그니처 | JSON 형식 → `Name: Value` 텍스트 형식 | T9 에서 헤더 자산이 텍스트로 직렬화되므로 |

## 현재 남은 것 (운영자용)

- **`scope.md` 를 CTF 당일 실제 허용 대역으로 교체**(현재 127.0.0.1/8 로컬 테스트 대역).
- 네트워크 접근 방식(VPN 등) 확정 시 `docker/compose.yaml` 접근 프로파일 채우기.
- 능동 정찰은 여전히 사람의 `GO <recon_id>` + `--approved` 가 없으면 실행되지 않는다.
- 능동 스캔용 대형 워드리스트는 미포함(SecLists 등을 `--wordlist`/`--dir-wordlist` 로 지정).
- **자가개선(T20)의 원본 반영 여부는 사람이 결정**: 변형본이 채택 게이트를 통과해도 원본에 반영하는
  것은 사람 판단. 변형본은 `scripts/variants/` 에 보존되고 `produced_by` 로 추적된다.
- **Django 해시 DB 는 4개 버전만 수록**: 실제 랩 버전 대응 시 `scripts/build_django_hash_db.py` 재구축.

---

## 만난 오류와 함정 (오케스트레이터가 반영할 것)

구현 과정에서 실제로 부딪힌 오류들이다. 전부 수정·검증했지만, 같은 종류의 문제는 다른
하네스(익스플로잇·보고)에서도 재현될 수 있으므로 원인·해결·교훈을 함께 기록한다.

| # | 증상 | 원인 | 해결 | 교훈 |
|---|------|------|------|------|
| E1 | `docker build` 실패: `COPY package.json … not found` | 빌드 컨텍스트를 `./docker` 로 줘서 루트 파일이 안 보임 | 루트를 컨텍스트로 `docker build -f docker/Dockerfile .` + `.dockerignore` | 컨텍스트와 Dockerfile 경로는 별개다. `.dockerignore` 로 targets/(민감정보)와 node_modules 배제 |
| E2 | 컨테이너에서 `collect_spa.py` 가 "playwright 미설치" | 베이스 `playwright/python` 이미지에 **브라우저(chromium-1179)만** 있고 playwright pip 패키지가 없음 | Dockerfile 에 `playwright==1.53.0` 설치(브라우저 빌드와 버전 일치 → 재다운로드 불필요) | "playwright 이미지"를 곧이곧대로 믿지 말 것. 브라우저와 패키지는 별개 |
| E3 | 컨테이너에서 `active_recon.py` "No such file" | 이미지에 COPY 된 scripts/ 가 **빌드 시점** 스냅샷 — 새 스크립트는 재빌드 전엔 없음 | 재빌드 + compose digest 재고정 | 코드 변경은 반드시 `docker build` 후 digest 갱신. **실제 동작한 digest 가 곧 진실**(manifest 의 `runtime_image_digest` 를 신뢰할 것) |
| E4 | 호스트→컨테이너 접속 `Connection refused` (host.docker.internal) | PowerShell `Start-Job` 백그라운드 프로세스가 **셸 세션 종료 시 함께 소멸** | `Start-Process`(detached)로 서버 기동, 바인딩은 `0.0.0.0` | Windows 에서 장수 프로세스는 detached 프로세스로. 컨테이너의 `localhost` 는 컨테이너 자신(루프백 주의) |
| E5 | `merge_fallback.py` 출력 중 `UnicodeEncodeError: 'cp949' codec can't encode '\u2014'` | Windows 콘솔 기본 인코딩 CP949 에서 한글+특수문자(`—`) 출력 크래시 | 모든 파이썬 스크립트에 `_utf8_stdio()`(stdout/stderr UTF-8 재구성) | 기록.md 6절의 인코딩 규율은 **콘솔 출력에도** 적용된다. 파일 저장만이 아니라 print 까지 |
| E6 | Node 테스트 `ERR_UNKNOWN_ENCODING` (`Buffer.from(x, "cp949")`) | Node 는 `cp949` 인코딩 미지원(utf8/latin1/base64/hex 등만) | CP949 바이트를 파이썬으로 미리 계산해 hex 로 고정 | 런타임 간 인코딩 대칭을 가정하지 말 것. 바이트(hex)로 계약을 고정 |
| E7 | `node --test tests/` → "Cannot find module …tests" | Node 24 는 `tests/` 인자를 모듈 경로로 해석 | glob 사용: `node --test "tests/*.test.mjs"` | 테스트 러너 인자 형식을 런타임별로 확인 |
| E8 | integration 테스트 실패: "미매칭 css 가 unknown 아님" | 테스트 헬퍼가 `.css` 를 `other` 로 분류 → fingerprint 의 unknown 발견 대상(js/css/html)에서 제외 | asset_kind 분류에 `.css → css` 추가 | 테스트 헬퍼의 분류가 대상 로직과 어긋나면 **테스트가 잘못된 기대**를 만든다. 검증 로직 자체를 의심 |
| E9 | merge 테스트에서 인용이 "fabricated"로 거부 | 테스트가 쓴 인용이 `"name": "acme-ui"`(큰따옴표)인데 파일은 `name: 'acme-ui'`(작은따옴표) | 인용을 파일 바이트와 정확히 일치하게 수정 | **바이트 정확**은 공백·따옴표 하나까지라는 뜻. 이것은 버그가 아니라 시스템이 의도대로 동작한 것 |
| E10 | fingerprint unknown 발견에서 해시/근거 불일치 리스크 | unknown 발견에 evidence_path=정규화본, asset_sha256=원본 해시를 쓰려다 발견 | 해시를 **evidence 파일 자체에서** 재계산(기록.md 5절 버그 재발 방지) | 같은 함정이 두 번: 근거 파일과 해시는 항상 같은 파일 기준 |
| E11 | vhost 발견 0건 | 워드리스트 후보("admin")와 픽스처 라우팅 이름("admin.corp.test") 불일치 | 후보 이름을 라우팅 이름과 일치시키는 워드리스트로 재검증 | baseline 억제 로직 자체는 정상. 픽스처의 호스트명이 후보 집합과 맞는지 먼저 확인 |
| E12 | `npm run check` 가 GO 가 안 됨 — `scope.md 허용 대역 미설정(UNSET)` | 게이트가 허용 대역 없이는 GO 불가 | **사람 승인**을 받아 로컬 테스트 대역(127.0.0.1/8) 임시 추가 | Scope 설정은 사람의 결정사항(AGENTS.md). 게이트는 UNSET 을 REVISE 로 유지하므로 CTF 당일까지 반드시 갱신 |
| E13 | 호스트에 nmap 없음 → 능동 스캔 부분 실패(exit 1) | 능동 도구는 호스트에 미설치 | 컨테이너에서 실행(nmap·gobuster 는 이미지 고정) | 능동 도구는 컨테이너가 단일 진실. 호스트는 게이트·수동 수집 전용 |
| E14 | 컨테이너에서 `extract_assets.py --cariddi` 가 cariddi 를 안 돌림 | 이미지가 `run_cariddi` 추가 **전** 스냅샷 (E3 재발) | 재빌드 + digest 재고정 | 스크립트 변경은 매번 재빌드. 이미지 digest 가 코드 진실 |
| E15 | `collect_web --depth` 크롤이 진입 참조만 수집 | 큐에 빈 바디(b"")를 넣어 **빈 바디 해시가 전부 동일** → 이후 항목 전부 스킵 | 해시 중복 판정을 **fetch 후 실제 바디** 기준으로 이동 | 자리표시자(placeholder) 데이터로 해시/등가 비교하지 말 것 |
| E16 | cariddi JSON 파싱 실패 | cariddi 는 **NDJSON(라인별 객체)** 출력, JSON 배열이 아님 | 라인별 `json.loads` 로 파싱 | 외부 도구 출력 형식은 실행해 보고 확인. "JSON 출력"이 배열을 뜻하지 않음 |
| E17 | cariddi 매치가 안 잡힘 (시크릿 0건) | cariddi 항목은 문자열이 아니라 `matches.secrets[{name, match}]` **중첩 객체** | `matches` 딕셔너리 + 객체의 `match`/`url`/`name` 필드 추출 | 외부 도구 스키마는 샘플 출력으로 검증 |
| E18 | 시크릿 픽스처가 정규식에 안 걸림 | 픽스처 토큰 길이가 실제 형식과 다름(ghp_+36, AIza+35) — 내가 39/40 자로 잘못 입력 | 형식에 맞게 수정, 연속 리터럴 유지 | 시크릿 시그니처는 **형식 규격이 곧 계약**. 픽스처도 규격을 지켜야 함 |
| E19 | 시크릿/엔드포인트 findings 가 전부 `asset_sha256 … fabricated` REVISE | 픽스처 파일을 교체 후 **manifest sha 를 갱신 안 함** → extract 가 낡은 sha 사용 | manifest 갱신 후 재실행 | 게이트가 낡은 증거를 정확히 잡아냄(기대 동작). 픽스처 갱신 절차에 sha 갱신 포함 |
| E20 | cariddi 시크릿 finding 이 **원문 전체를 evidence_quote 로 노출** | 마스킹 규율을 cariddi 파싱 경로에 미적용 | 시크릿은 형식 프리픽스만 인용 + `secret_masked`(앞4자+길이) | 시크릿 원문은 git 추적되는 findings.json 에 **절대** 두지 말 것(observation/gitignore 만) |
| E21 | `merge_fallback` 테스트 추가 중 `test(` 선언을 덮어씀 | edit 의 oldString 이 테스트 선언 첫 줄을 삼켜 **다음 테스트 본문이 테스트 없이 방치** | 선언 복원 후 `npm test` 로 회귀 확인 | 대량 edit 는 인접 구조(테스트 선언)를 건드릴 수 있음. 편집 후 해당 파일 테스트 확인 |
| E22 | T18 테스트 추가 후 "jQuery confirmed" 실패 | **E21 재발**: `test(` 선언을 또 덮어써 첫 테스트 본문이 소실되고 다음 테스트 본문이 뒤섞임 — 원인이 fingerprint 버그로 오인될 뻔 | 통합 테스트 파일 전체 재작성(17개 테스트 구조 정리) | 테스트 파일에 테스트를 앞에 삽입할 때 **인접 선언 보존을 반드시 확인**. 대규모 테스트 파일은 전체 재작성이 안전. "테스트 실패"가 스크립트 버그인지 테스트 파일 손상인지 먼저 구분 |
| E23 | T21 디코드 strings 파일 findings 가 `asset_sha256 … fabricated` REVISE | 파일엔 `\n`.join(lines)+"\n" 을 쓰면서 **해시는 "\n" 없이** 계산(쓰는 바이트≠해시 바이트, 기록.md 5절 재발) | 해시를 실제 쓰는 `content` 에서 계산 | 파생 파일 생성 시 **실제로 쓰는 바이트와 해시를 항상 동일 변수로**. E10/E19 와 같은 함정이 세 번째 |

## 부족했던 점 · 남은 위험 (오케스트레이터 주의)

1. **워드리스트 미배포 → T13 로 일부 해소**: `wordlists/` 디렉터리 + compose 마운트 표준화.
   여전히 대형 워드리스트(SecLists)는 미포함 — 오케스트레이터가 `wordlists/` 에 넣어 컨테이너와 공유.
2. **헤더/쿠키 1급 자산 → T9 로 해소**: 정적·SPA 양쪽이 헤더/쿠키 자산을 등록, 헤더 시그니처가
   SPA 타깃에도 적용된다. (단, SPA 의 각 하위 XHR 응답 헤더는 진입 헤더만 캡처 — 후속 보강 후보.)
3. **vhost/능동 폴백은 HTTP 우선**: 평문 HTTP vhost 는 동작하나 HTTPS vhost(SNI) 는 파이썬 폴백에서
   미처리(T13 에서 경고만). gobuster vhost 경로 사용. 대형 워드리스트 부재가 여전히 제약.
4. **nmap 배너 파싱 → T13 로 정밀화**: `parse_banner()` 로 product/version 토큰 분리, 버전 미상 시
   inferred. 다중 토큰 배너에서도 정확도 향상. (경계: "(Python 3.x)" 같은 중첩 표기는 version 에 들어감)
5. **merge_fallback 의 exit 1 의미**: 판정 중 하나라도 거부(미매칭 asset_id, fabricated 등)되면 exit 1.
   유효 병합과 거부가 공존해도 실패로 보이므로, 오케스트레이터는 **exit 1 = "일부 판정 검토 필요"**
   로 해석해야 한다(거부 사유가 stdout 에 나온다).
6. **second_pass 는 confirmed 만 자동 선정**: `--prepare` 기본값이 confirmed. 고가치 inferred 도
   재판정하려면 `--finding-id` 로 명시.
7. **통합 테스트가 저장소 targets/ 를 사용**: 정상 시 자체 정리하지만 중간에 죽으면 `it-<ts>` 타깃이
   남을 수 있고, 그 상태에서 `npm run check`(hint 없음) 는 AMBIGUOUS 를 낸다. 잔여 타깃 확인·정리를
   세션 Cleanup 에 포함할 것.
8. **시그니처 커버리지는 여전히 유한**: 난독화·중소형 프레임워크는 `unknown`(명시 발견 + unmatched)으로
   남긴다. "모르면 모른다"가 정답이므로 억지로 채우지 말고, 다음 하네스(CVE 매핑) 입력은
   `provenance: confirmed` 만 자동 진행, 그 이하는 재검증 요구(workflow 표준 계약).
9. **`runtime_image_digest` 는 수집기 외 명령에서도 기록됨**: normalize/fingerprint 실행 때도
   manifest 를 다시 쓴다(같은 digest 라 무해). 만약 디버깅 중 digest 가 안 바뀌는 걸 보면
   "컨테이너가 그 digest 로 떠 있다"는 뜻이고, 코드 반영은 재빌드 후에만 일어난다(E3).

**Phase 2 추가 제약 (오케스트레이터 주의)**
10. **Werkzeug→Flask 매핑은 시기(범위) 추정**: 정확한 Flask 버전이 아니라 릴리스 시기다. CVE 하네스는
    이 매핑 산출(Flask inferred, version_bound)을 "확정 버전"으로 취급하면 안 된다.
11. **Django 해시 DB 는 4개 버전만 수록**(3.2.25/4.2.11/5.0.6/5.1.6): 실제 랩 버전이 그 밖이면
    `scripts/build_django_hash_db.py --versions …` 로 재구축. 출처는 공식 PyPI 휠.
12. **cariddi JSON 스키마는 v1.4.6 에 고정**(이미지 버전 고정): 업그레이드 시 `extract_assets.py` 의
    파싱(matches 중첩) 재검증 필요.
13. **T14 S3 공개 확인은 미실행(개발 세션)**: `--approved-for-public` 이 없는 한 차단되고, 실제
    공인 접근은 CTF 허용 시에만. AWS 신호(--signal-only)는 로컬 검증만 함.
14. **능동 DNS(vhost/DNS) 해석은 CTF 네트워크에서만 의미**: 로컬에서는 미해석이 정상. VPN 확정 후
    컨테이너에서 실행(scope 게이트는 그대로 동작).

**Phase 4(T21) 추가 제약**
15. **string-array 언패커는 단순형만**: javascript-obfuscator 의 rotate("crazy") 변형(push/splice/shift 로
    배열 런타임 변조)은 미지원 → unknown 보존. 완전 커스텀/VM 난독화는 시도하지 않는다(경계 규율).
16. **인코딩 디코더는 가역성 체크 기반**: base64/hex/url 로 보이지만 디코드가 비가독(바이너리)이면
    폐기 → 일부 진짜 인코딩도 놓칠 수 있음(오탐보다 미탐 우선). "실제 유효한 숨은 값" 해석은 inferred.
17. **source map 수집은 추가 요청 발생**: JS 가 sourceMappingURL 을 참조하면 `.map` 을 fetch 하므로
    자산 수가 늘고 요청이 추가된다(참조 자산이므로 수동 범위). `.map` 이 공개된 채 배포된 경우 원본
    소스가 그대로 노출된다는 신호로 해석 가능.
18. **webcrack/synchrony 미통합**: 컨테이너에 node 가 없어 순수 파이썬으로 구현(결정론적·컨테이너 무관).
    정교한 난독화가 필요한 경우 성숙 도구를 이미지에 고정하는 것으로 확장 가능.

**Phase 5(T22) 추가 제약**
19. **능동 방어 프로브는 방어를 건드릴 수 있다**: `--payloads`/`--rate` 는 차단·IP 밴을 유발할 수 있음 —
    반드시 GO+최소 프로브, 트립 시 즉시 중단·사람 보고. 패시브(WAF/CDN 시그니처)를 먼저 돌려 능동
    강도를 정하는 입력으로 쓸 것.
20. **wafw00f 의존**: wafw00f JSON 스키마(`firewall`/`detected`)는 v2.4.2 에 고정 — 업그레이드 시 파싱 재검증.
    wafw00f 가 요청을 보내므로 능동(컨테이너 실행 권장).
21. **CDN/WAF 복수 탐지 해석**: Cloudflare 앞단은 cf-ray(CDN)와 __cf_bm(WAF)이 같이 잡히는 등 겹침이 자연스럽다 —
    복수 confirmed 는 오류가 아니라 적층 방어다. 순수 패시브 IDS 는 `unknown`(지어내지 않음).
22. **scope.md 에 127.0.0.1/8 재추가**: 로컬 픽스처(waf_server 등) 검증용. (배포 시 scope.md 는 UNSET 으로 초기화.)
