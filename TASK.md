# TASK.md — External Recon Harness (외부 정찰 하네스) 구현 작업 지시서

> **역할 분리**: 전체 설계·계약·게이트는 확정돼 있다. 이 문서는 **구현을 담당하는 코딩 에이전트**를
> 위한 작업 지시서다. 각 태스크는 콜드 스타트 전제로 **자기완결적**으로 작성했다.
>
> **진행 상황**: 초기 T1~T8은 **완료**됐다(수행 결과·함정·남은 위험은 [TASK-RESULT.md](TASK-RESULT.md) 참조).
> 아래 "완료된 작업"에서 요약하고, 이번 문서의 실제 지시는 **Phase 2 (T9~T14)**다.
> Phase 2의 핵심은 **핑거프린팅 확장 트랙(T9~T12)** — 서버사이드(Flask/Django/PHP/nginx…)까지
> 커버하도록 헤더·쿠키를 1급 매칭 자산으로 올리고, 폭과 깊이를 동시에 넓힌다.

---

## 0. 모든 에이전트 공통 규칙 (작업 시작 전 반드시 읽기)

1. **먼저 읽어라**: [AGENTS.md](AGENTS.md), [harness/policies/invariants.md](harness/policies/invariants.md),
   [harness/workflow.md](harness/workflow.md), [README.md](README.md), 그리고 [TASK-RESULT.md](TASK-RESULT.md)의
   "만난 오류와 함정" 표(같은 함정 재발 방지).
2. **완료 기준은 게이트다.** 산출물은 `npm run check -- <target>` 에서 의도한 결과(GO/REVISE/STOP)를 내야 한다.
   "코드가 돌아간다"가 아니라 "게이트가 검증한다"가 완료다. 회귀는 `npm test`로 고정한다.
3. **환각 통제 규율을 깨지 마라**:
   - AI 산출은 Evidence가 아니다. `provenance`는 `confirmed`/`inferred`/`guess`/`unknown` 4등급.
   - AI 추론은 `confirmed`로 **자가 승격 금지**. `confirmed`는 결정론 도구 매칭 또는 second-pass 재검증만.
   - 모든 버전/제품 단정은 `evidence_path`(실재 파일) + `evidence_quote`(그 파일의 실제 바이트 부분 문자열) + `asset_sha256`(재계산 일치)로 바인딩. `unknown`은 정답이다.
   - **인코딩 규율**: 해시·인용 대조는 항상 **바이트 기준**. 텍스트 파일 저장·**콘솔 출력**은 표준 UTF-8.
     (CP949/BOM 대응·`_utf8_stdio()` 패턴이 이미 있음 — 그대로 따를 것. 근거: TASK-RESULT E5/E6.)
4. **결정론 우선, AI는 fallback.** 수집·정규화·매칭·검증은 스크립트로 결정론적이게. AI는 판단에만.
5. **의존성은 작업 중 직접 설치하고 기록하라.** 각 태스크의 "설치" 항목대로 설치하고,
   설치 명령을 `README.md`·`requirements.txt`·`docker/Dockerfile`에 반영한다.
6. **실패·미매칭·UNKNOWN을 삭제하지 마라.** Observation으로 보존한다.
7. 스코프 밖(`scope.md` 허용 대역 밖) 타깃 접근 금지. 능동 정찰은 `GO <recon_id>` + `--approved` 뒤에만.
8. **능동 도구는 컨테이너가 단일 진실.** nmap/gobuster 등은 호스트에 없을 수 있다(TASK-RESULT E13).
   컨테이너에서 실행하고, 코드 변경은 반드시 `docker build` 후 compose digest를 갱신한다(E3).
9. **자가개선은 런타임 계약이다.** 스크립트 자가개선 규율(사본 작업·검증기 불변·로그)은
   [AGENTS.md](AGENTS.md) "스크립트 자가개선"과 [harness/policies/self-repair.md](harness/policies/self-repair.md)에
   있다. 빌드 에이전트도 현장에서 스크립트가 깨지면 그 규율을 따른다. **T20은 그 정책을 실행할
   메커니즘(변형본 디렉터리·로그 기록·가드레일 테스트)을 구현하는 태스크**다.

---

## 실행 아키텍처 — Docker 컨테이너 실행 + 호스트 검증 (T1에서 구축됨)

```
┌─────────────── 호스트(로컬) ───────────────┐
│  Claude Code (오케스트레이터)               │
│    │ 위임                                    │
│    ▼                                         │
│  서브에이전트 ─up -d/exec─▶ recon 컨테이너   │
│                            (nmap/gobuster/   │
│                             playwright/py)   │
│    ▲                            │ 원본+해시   │
│    │ 독립 재검증                 ▼            │
│  게이트(check-recon.mjs) ◀── 마운트 볼륨     │
│    (호스트에서 해시·인용 재계산)  targets/    │
└──────────────────────────────────────────────┘
```

**장수 컨테이너 + `docker exec`** (명령마다 껐다 켜지 않음). 컨테이너는 수집·실행만, 검증은 호스트
게이트가 파일에서 독립적으로. 네트워크 접근 방식(VPN 등)은 **미정** — `docker/compose.yaml`의 접근
프로파일로 교체 가능하게 두고, 코어는 접근 방식과 무관하게 동작한다.

---

## 완료된 작업 (T1~T8) — 요약

세부 수행·검증·함정은 [TASK-RESULT.md](TASK-RESULT.md).

| # | 작업 | 결과 |
|---|------|------|
| T1 | Docker 실행 환경 | `docker/Dockerfile`+`compose.yaml`(장수 컨테이너, 이미지 `@sha256` 고정), `scripts/recon.mjs`(exec 래퍼, `runtime_image_digest` 기록) |
| T2 | AI fallback 추론 | `harness/prompts/fallback-inference.md`, `scripts/merge_fallback.py`(인용 바이트 검증·confirmed 거부·unknown 보존) |
| T3 | 2차 재검증 | `harness/prompts/second-pass-verify.md`, `scripts/second_pass.py`(contradict → confirmed 강등) |
| T4 | vhost 발견(능동) | `scripts/discover_vhost.py`(baseline 오탐 억제, GO 게이트) |
| T5 | 능동 정찰(능동) | `scripts/active_recon.py`(nmap `-sV`+디렉터리 열거, GO·스코프 게이트) |
| T6 | 시그니처 확장 | Angular/Vue/Next/WordPress/nginx/Apache/PHP/Laravel JSON + `fingerprint.py`의 `match_headers()`(헤더 탐색) |
| T7 | 라이브 SPA 검증 | `requirements.txt`, React 18 픽스처 end-to-end GO, 런타임 Fiber 지문 캡처 |
| T8 | 테스트 | `tests/*.test.mjs`+`tests/test_python.py`, `npm test`(node 12 + py 10 통과) |

> **운영자 필수(TASK-RESULT "남은 것")**: ① `scope.md`를 CTF 당일 실제 대역으로 교체(현재 로컬
> 테스트용 `127.0.0.1/8`). ② 접근 방식 확정 시 compose 프로파일 채우기. ③ 능동 정찰은 `GO`+`--approved`
> 없이는 미실행. ④ 대형 워드리스트는 미포함 — 마운트/지정 필요.

---

# Phase 2 — 남은 작업 (T9~T14)

## ▶ 핑거프린팅 확장 트랙 (T9 → T12, 순서대로)

T6에서 프론트엔드 문자열 시그니처와 **헤더 매칭 함수**까지는 들어갔다. 그러나 서버사이드
(Flask/Django 등)를 제대로 잡으려면 아래 순서가 필요하다. **이유**: Flask/Django는 클라이언트 JS에
버전을 남기지 않는다. 지문이 **헤더·쿠키·에러페이지·기본 경로·버전별 정적 자산**에 있다. 그런데 현재
`match_headers()`는 `entry-headers.json`만 읽는 **정적 전용 bespoke 함수**이고 **쿠키는 매칭 표면에
없다.** 그래서 substrate부터 고친다.

---

### T9. 헤더·쿠키를 1급 매칭 자산으로 (substrate, 우선순위 1)

**목적**: 응답 헤더와 쿠키를 정규 자산으로 승격해, 일반 매칭 루프·증거 바인딩·게이트 재검증이
그대로 적용되게 한다. (서버사이드 지문의 전제조건.)

**왜**: 현재 헤더는 `fingerprint.py`의 특수 함수로만, 쿠키는 아예 매칭이 안 된다. 그리고 헤더
핑거프린트가 `collect_web`(정적) 전용이라 **SPA 타깃은 nginx/PHP 헤더 지문을 놓친다**(TASK-RESULT 위험 #2).

**접근**:
- 두 수집기(`collect_web.py`, `collect_spa.py`) 모두 응답 헤더와 쿠키를 **표준 텍스트로 직렬화**해
  `captures/raw/`에 저장하고 **manifest 자산으로 등록**한다:
  - `asset_kind: "header"` — 예: `__headers__.txt`(각 응답의 `Name: Value` 라인). SPA는 진입 응답 헤더를
    포함(collect_spa가 최초 document 응답 헤더를 별도 캡처).
  - `asset_kind: "cookie"` — Set-Cookie / 브라우저 쿠키를 `name=value; attrs` 라인으로. **쿠키 값 원문은
    민감**하므로 raw는 gitignore 대상(`captures/raw/`)에 두고, 이름·플래그·형식만 지문에 쓴다.
  - 각 자산에 `asset_sha256` 기록. 바이트 기준 인용 규율 준수.
- `fingerprint.py`의 일반 자산 루프가 `header`/`cookie` kind도 처리하도록 정리하고, 기존
  `match_headers()`는 이 경로로 **흡수/폐기**(중복 제거). 근거는 여전히 `harness/signatures/*.json` 데이터.
- 게이트·`asset_kind` 분류 헬퍼(테스트 포함)에 `header`/`cookie` 추가(TASK-RESULT E8 교훈).

**완료 기준**: 정적·SPA 양쪽에서 헤더/쿠키가 manifest 자산으로 잡히고, 헤더/쿠키 시그니처가
`confirmed`/`inferred`로 매칭되며 게이트 GO. 회귀 테스트 추가.

**환각 통제**: 헤더/쿠키도 파일로 저장→해시·바이트 인용 재검증. 쿠키 값 원문은 report 비노출(마스킹).

---

### T10. Flask/Django + 서버사이드 쿠키·기본자산 시그니처 (breadth, 우선순위 1)

**목적**: 사용자 요청 제품(Flask, Django)과 그 계열의 서버사이드 지문을 시그니처 데이터로 추가한다.

**왜**: T9로 헤더·쿠키가 매칭 가능해지면, 서버사이드 제품을 근거 기반으로 특정할 수 있다.

**접근** (전부 `harness/signatures/*.json` 데이터 — 스크립트 로직 금지):
- **Flask** (`flask.json`):
  - 헤더 `Server: Werkzeug/(?P<version>[\d.]+) Python/…` → Werkzeug 정확 버전 `confirmed`(단, Flask 버전
    자체는 아님 — reasoning에 "Werkzeug 버전"이라 명시. Flask 매핑은 T11).
  - 쿠키: Flask 서명 세션 쿠키 형식(`session=eyJ...` base64 JSON + `.` 서명, itsdangerous) → Flask 사용
    `inferred`/`guess`. 쿠키 이름·형식만 근거로(값 원문 아님).
  - Werkzeug 인터랙티브 디버거 페이지 마커(에러페이지, 능동 프로브 시 — T12).
- **Django** (`django.json`):
  - 쿠키 `csrftoken`, `sessionid` 존재 → Django `inferred`.
  - 헤더/기본 페이지: `/admin/` 로그인 페이지 마커, DRF browsable API 마커.
  - DEBUG=True 노란 에러페이지(버전 노출) — 능동 프로브(T12)에서 트리거.
- PHP/nginx/Apache는 T6에서 헤더 기반으로 됨 — T9 substrate로 이관되면 그대로 동작 확인.

**완료 기준**: Flask/Django 픽스처(헤더·쿠키·기본 페이지)로 매칭 확인, 게이트 GO, 회귀 테스트.
근거 없는 광역 매칭(오탐) 금지.

---

### T11. 관용구·산출물 → 버전 범위 깊이 확장 (depth, 우선순위 2)

**목적**: 버전을 숨겨도 **범위**를 도출하는 능력을 React 외 제품으로 넓힌다(강의의 "코드 특징으로
버전 특정").

**왜**: 정확 버전 문자열은 숨기기 쉽다. 관용구·산출물 기반 범위 추론이 숨긴 타깃의 실전 대응이다.
현재 이 능력은 React에만 있다.

**접근**:
- **프론트엔드 관용구→범위** (`*.json` 데이터): Vue(옵션 API vs `createApp`→2 vs 3), Angular(`ng-app`
  vs `ngVersion`/Ivy 마커), Next(`__NEXT_DATA__` 구조 변화) 등 버전 시기 구분 규칙.
- **서버사이드 산출물→버전** (데이터 + 소형 매핑 테이블):
  - Werkzeug 버전 → Flask 릴리스 시기 매핑 테이블(`harness/signatures/maps/werkzeug-flask.json` 같은
    데이터). fingerprint가 confirmed Werkzeug 버전을 이 표로 Flask 범위(`inferred`)로 변환.
  - Django admin **버전별 정적 자산 해시 DB**(`/static/admin/css/base.css` 등의 sha256→Django 버전).
    자산 해시가 DB와 일치하면 Django 버전 `confirmed`(자산이 실재·해시 일치). 해시 DB 구축 방법(공식
    릴리스에서 추출)과 출처를 문서화.
- 매핑 테이블/해시 DB는 **데이터로 분리**하고 출처를 기록. 매핑 로직 최소화.

**완료 기준**: 대표 제품에서 버전 범위/정확버전이 근거와 함께 나오고 게이트 GO. 오탐 회귀 테스트.

---

### T12. 서버사이드 능동 프로브 지문 (active, GO-gated, 우선순위 2)

**목적**: 기본 경로·에러 유발로만 드러나는 서버사이드 버전 지문을 능동 정찰로 수집한다.

**왜**: `/admin/`, `/static/admin/…`, `/wp-login.php`, 강제 에러(DEBUG 페이지) 등은 타깃을 건드리므로
**수동이 아니라 능동**이다. 여기에 고신호 버전 근거가 몰려 있다.

**접근**:
- `scripts/active_recon.py`(T5)에 서버사이드 프로브 셋을 추가: 제품 힌트가 있을 때 해당 기본 경로를
  조회하고 응답을 Observation으로 보존, 마커/버전을 findings로. **`GO <recon_id>`+`--approved`+스코프 게이트**.
- 프로브 대상은 T10/T11 시그니처와 연결(Django admin static → T11 해시 DB, WordPress `/wp-login.php` 등).
- 파괴적·인증 우회 시도 금지(scope STOP 규율).

**완료 기준**: 픽스처로 능동 프로브가 GO 승인 시에만 실행되고, 수집 근거로 버전 발견→게이트 GO.

---

## ▶ 운영·보강 트랙

### T13. 능동 도구 운영 보강 (우선순위 2)

**목적**: TASK-RESULT "남은 위험"의 운영 결함을 메운다.

**접근**:
- **워드리스트 마운트/배포**: SecLists 등 워드리스트를 컨테이너에 마운트하는 경로를 compose/문서에
  표준화. gobuster 기본 경로 부재를 문서화하고 `--dir-wordlist` 필수임을 명시(위험 #1).
- **HTTPS vhost(SNI) 폴백**: 파이썬 폴백의 평문 전용 한계를 보완하거나, HTTPS는 gobuster/ffuf 경로로
  라우팅(위험 #3).
- **nmap 배너 파싱 정밀화**: `product`/`version` 토큰 분리를 개선(위험 #4). 단, 불확실하면 `inferred`.
- **merge_fallback exit 코드 의미 문서화**: 일부 거부 시 exit 1의 해석을 오케스트레이터 문서에 명시(위험 #5).
- **잔여 타깃 정리**: 통합 테스트 중단 시 `it-<ts>` 타깃 잔여 → 세션 Cleanup에 포함(위험 #7).

**완료 기준**: 각 항목이 문서/스크립트에 반영되고 관련 테스트/스모크 통과.

---

### T14. AWS 인프라 정찰 (우선순위 3)

**목적**: 사전 힌트("AWS 인프라 사용")에 대응하는 정찰 모듈.

**왜**: 웹 자산 정찰만으로는 AWS 계층(S3·메타데이터·IAM)을 못 본다. CTF에 AWS가 등장하면 별도 표면이다.

**접근** (전부 스코프·GO 규율 준수):
- S3 버킷 열거(추정 이름·공개 여부), 정적 사이트 호스팅 흔적.
- SSRF 등으로 접근 가능한 경우의 인스턴스 메타데이터(`169.254.169.254`)는 **익스플로잇 하네스 영역**과
  경계가 겹치므로, 정찰 하네스는 "메타데이터 접근 가능성 신호"까지만 기록하고 실제 취득은 위임.
- 결과는 동일 finding 스키마로. 공인 AWS 엔드포인트 접근은 scope 예외 처리 방식을 문서화(CTF가 허용한
  범위만).

**완료 기준**: AWS 신호가 finding으로 근거와 함께 기록되고 게이트 GO. 범위 밖 접근은 STOP.

---

## ▶ 외부 도구·기법 통합 트랙 (T15~T17)

> 근거: 외부 오픈소스 두 곳을 분석해 우리 공백을 메운다.
> **cariddi**(github.com/edoardottt/cariddi — Go 웹 크롤러/스캐너: 깊이 크롤·시크릿/엔드포인트/에러
> regex 추출·응답 저장·JSON 출력)와 **recon-skills**(github.com/uphiago/recon-skills — AI 에이전트용
> 스킬 팩: AGENTS.md·validator·서브도메인/DNS·JS 시크릿·클라우드 피벗·chains/meta taxonomy).
> recon-skills의 계약+validator 구조는 우리 AGENTS+게이트와 사실상 동형이라, 우리 설계의 정당성
> 근거이자 **오케스트레이터 taxonomy(recon/auth/infra/chains/meta)** 참고자료다(오케스트레이터 레벨,
> 이 하네스 범위 밖 — [기록.md](기록.md)에 반영).

---

### T15. 자산 기반 추출 패스 — 시크릿·엔드포인트·에러버전 (우선순위 1)

**목적**: 이미 수집·정규화한 자산에서 **시크릿/토큰·API 엔드포인트·에러/스택트레이스(버전 누출)**를
추출한다. 현재 파이프라인의 큰 공백(cariddi가 하는 일).

**왜**: 시크릿·엔드포인트는 정찰의 고가치 산출물이고, 에러/스택트레이스는 서버사이드 버전을 흘린다
(T11/T12와 연결). 자산은 이미 디스크에 있으므로 결정론적 regex 패스로 저비용 확보 가능.

**접근**:
- **cariddi를 도구로 통합**(재발명 금지): `docker/Dockerfile`에 cariddi 설치, `scripts/extract_assets.py`가
  cariddi를 수집 자산/타깃에 돌리고 **JSON 출력을 finding 스키마로 파싱**. 순수 파이썬 regex 폴백도 제공
  (오프라인·컨테이너 미사용 시).
- **증거 바인딩 + 등급 분리**(환각 통제 핵심):
  - 매치된 문자열의 **존재 자체는 confirmed**(evidence_path=자산, evidence_quote=매치 바이트, asset_sha256).
  - **"이것이 진짜 유효한 시크릿/실사용 엔드포인트인가"는 inferred**(regex 오탐 가능). reasoning에 명시.
  - 에러페이지의 버전 문자열은 confirmed(원문 실재), 그 버전이 제품 버전이라는 해석은 T11 규율 따름.
- **시크릿은 report 마스킹**: 원문은 `captures/raw/`(gitignore)에만, finding/report엔 마스킹 형태
  (앞 4자+길이 등). 쿠키(T9)와 동일 규율.
- 엔드포인트 목록은 다음 하네스(익스플로잇) 입력이 되도록 finding에 구조화.

**설치**: `go install github.com/edoardottt/cariddi/cmd/cariddi@latest`(또는 릴리스 바이너리) — Dockerfile에.

**완료 기준**: 시크릿/엔드포인트/에러버전이 근거 바인딩되어 finding에 나오고 게이트 GO. 오탐은 inferred로
등급 하향, 시크릿 마스킹 확인. 회귀 테스트(픽스처에 심은 가짜 키/엔드포인트/에러 검출).

**환각 통제**: 문자열 존재=confirmed / 해석=inferred 분리, 마스킹, 게이트 바이트 재검증.

---

### T16. 스코프 제한 크롤 (우선순위 2)

**목적**: 진입 1레벨을 넘어 **깊이 제한 링크 발견**으로 더 많은 자산·페이지를 수집한다(cariddi 크롤 모델).

**왜**: 엔터프라이즈 랩은 다중 페이지·다중 앱이다. 1레벨 수집은 자산 표면을 좁게 본다.

**접근**:
- `collect_web.py`/`collect_spa.py`에 `--depth N`(기본 1, 상한 명시)·동시성·지연 옵션 추가. 발견 링크 중
  **허용 대역·동일 스코프 내부만** 따라간다. 외부 도메인은 기록만 하고 크롤하지 않는다.
- 크롤은 요청량이 늘어 능동에 가깝다 → **기본 저강도(depth 1)**, 상향은 `--depth`로 명시적 선택. 대역 밖
  링크 관찰 시 STOP 규율. 모든 응답은 Observation·manifest 자산으로 보존(중복 해시 제거).

**완료 기준**: depth 제한 크롤로 추가 자산이 manifest에 잡히고 게이트 GO. 대역 밖 미크롤 확인.

---

### T17. 서브도메인·DNS 발견 (우선순위 3)

**목적**: 서브도메인/DNS 자산을 발견한다(recon-skills의 공백 항목). vhost(T4)와 상보적.

**왜**: 가상 네트워크·엔터프라이즈 환경은 다수 서브도메인/내부 DNS를 갖는다. vhost(Host 헤더)와 별개로
DNS 레벨 자산이 있을 수 있다.

**접근**:
- **passive**: 제공된 DNS·인증서(SAN)·수집 자산 내 도메인 문자열에서 서브도메인 수집(저위험).
- **active**: 워드리스트 기반 DNS 브루트/해석 — **`GO <recon_id>`+`--approved`+스코프 게이트**. 발견
  호스트는 허용 대역 내에서만 후속 수집. 결과는 Observation·finding.
- 대역 밖으로 해석되는 항목은 기록만(자동 확장 금지, STOP 규율).

**완료 기준**: 픽스처로 passive 수집 동작, active는 GO 승인 시에만 실행, 발견 결과 게이트 GO.

---

# Phase 3 — 검토에서 나온 수정 + 자가개선 (T18~T20)

> 근거: 정찰 하네스 코드 검토(설계자 확인). T18은 **현재 데이터 유실이 실제로 발생**하는 결함이라
> 다음 실행 전에 최우선으로 고친다.

---

### T18. `fingerprint.py` 멱등 병합 — 능동/fallback 결과 유실 방지 (우선순위 0, 최우선)

**목적**: fingerprint 재실행이 다른 스크립트의 발견을 파괴하지 않게 한다.

**왜 (확인된 결함)**: 현재 `fingerprint.py`는 기존 `findings.json`을 읽지 않고 통째로 덮어쓴다
([fingerprint.py](scripts/fingerprint.py) `out={..., "findings": findings}` → `json.dump`). 그런데
`active_recon.py`(nmap `append_finding`), `merge_fallback.py`, `second_pass.py`는 모두 findings.json에
**append/수정**한다. 특히 **T12 `active_recon.py --server-probe`가 fingerprint를 subprocess로 재실행**
([active_recon.py](scripts/active_recon.py) `server_probe()`)하므로, 같은 명령 안에서 방금 붙인 nmap
`confirmed` 발견이 **자기파괴**되고, 파이프라인상 `merge_fallback`(T2)·`second_pass`(T3) 결과도 소실된다.
(실증됨: fingerprint 재실행 시 append된 발견 3→2로 소실.)

**접근**:
- `fingerprint.py`가 시작 시 기존 `findings.json`을 읽고, **출처가 `fingerprint.py:*`(또는 헤더/쿠키/
  매핑/해시 DB 등 fingerprint 자신이 생성한 것)인 발견만 교체**한다. 다른 출처(`active_recon.py:*`,
  `fallback-inference:*`, `second-pass` 흔적, `extract_assets.py:*`, `discover_*` 등)의 발견은 **보존**.
- 판별은 `verified_by` 접두 또는 finding에 `generated_by` 필드를 추가해 결정론적으로. `unknown` 명시
  발견도 fingerprint 소유이므로, 재실행 시 해당 자산이 여전히 미매칭이면 갱신, 매칭되면 교체.
- `unmatched`도 동일 원칙으로 재구성(다른 스크립트가 소비/보존한 항목 파괴 금지).

**완료 기준**: nmap 발견 append → `--server-probe`(fingerprint 재실행) 후에도 nmap 발견 **잔존**.
merge_fallback/second_pass 결과가 fingerprint 재실행에도 보존. **유실 회귀 테스트를 `tests/`에 추가**
(T12/T2/T3 각각). 게이트 GO.

---

### T19. 검토 발견 결함 수정 (우선순위 1)

**#3 `discover_vhost` FQDN 지원**: 기본 워드리스트가 bare label(`admin`)이라 실제 vhost(`admin.corp.htb`)를
못 잡는다. `--domain <base>` 옵션을 추가해 `word + "." + base`로 Host 후보를 생성(파일 워드리스트가
FQDN이면 그대로 사용). 재수집 안내 명령도 FQDN으로 출력.

**#4 `active_recon` 디렉터리 발견 스키마 정리**: 현재 `version` 필드에 HTTP status(200), `product=
"http-path"`로 스키마를 오용한다([active_recon.py](scripts/active_recon.py)). 경로 발견은 별도 형태로 —
예: `asset_kind: "path"`, `product`/`version`은 `UNSET`, status는 별도 필드(`http_status`)나 reasoning에.
다음 하네스가 (product, version)로 CVE 조회할 때 오염되지 않게.

**#5 scope 파서 주석 방어**: `허용 대역:` 파서가 주석(`<!-- ... -->`) 안의 예시 라인도 매칭할 수 있다
(활성 라인 삭제 시 주석 예시 대역이 조용히 활성화). 게이트([lib/checks.mjs](scripts/lib/checks.mjs))와
`active_recon.py`/`discover_vhost.py`/`discover_dns.py`의 scope 파서 모두 **주석을 먼저 제거**한 뒤
`허용 대역:`을 찾도록 수정. 회귀 테스트 추가.

**완료 기준**: 각 항목 회귀 테스트 통과, 게이트 GO.

---

### T20. 스크립트 자가개선(self-repair) 메커니즘 + 로그 (우선순위 1)

**목적**: [self-repair.md](harness/policies/self-repair.md) 정책(이미 작성됨)을 **실행할 메커니즘**을
구현한다. 정책이 규정한 사본 작업·검증·로그·가드레일을 코드로 강제한다.

**왜**: CTF 당일 환경은 미지수다. 수집기가 특정 사이트에서, 도구 래퍼가 특정 버전에서 깨질 수 있다.
에이전트가 즉석 수정하되, **통제(게이트·증거 규율)를 훼손하지 않고 재현 가능하게** 만들어야 한다.

> 정책 문서는 이미 존재한다([self-repair.md](harness/policies/self-repair.md), [AGENTS.md](AGENTS.md)
> "스크립트 자가개선", [invariants.md](harness/policies/invariants.md) "신뢰 앵커 불변"). 이 태스크는
> **문서 작성이 아니라 그 정책을 실행 가능하게 만드는 것**이다.

**접근** (정책 §3~§4를 코드로):
- `scripts/variants/` 디렉터리 규약 + 산출물 `produced_by` 필드(어느 변형본이 산출했는지) 지원.
- 자가개선 로그 기록 헬퍼: `targets/<host>/self-repair-log.md`(+ `.json`) 표준 형식으로 append.
- **가드레일 강제**: 신뢰 앵커(`check-recon.mjs`, `lib/checks.mjs`, `AGENTS.md`, `invariants.md`) 경로에
  대한 자가수정 시도를 **거부/경고**하는 체크(예: variants 생성 시 대상 경로 화이트리스트 검증).
- 채택 게이트: 변형본 산출 후 `npm test` + 타깃 게이트를 통과해야 채택하는 흐름(스크립트/문서화).

**완료 기준**: 의도적으로 깨진 상황(예: 특정 응답 형식) 픽스처에서 절차대로 사본 생성·수정·검증·로그가
남고, **신뢰 앵커 경로 자가수정 시도는 가드레일이 차단**(테스트로 증명), 게이트 GO.

**환각 통제**: 검증기를 대상이 못 고치게 잠그고(가드레일), 개선본 산출물도 동일 게이트로 재검증하며,
모든 변경을 근거와 함께 로그로 남겨 재현·감사 가능하게 한다.

---

## 권장 순서

> Phase 1(T1~T8)·Phase 2(T9~T17)는 완료됨(TASK-RESULT.md). 다음은 **Phase 3(수정·자가개선)을 최우선**으로.

1. **T18(fingerprint 멱등 병합)** — ⚠️ 현재 데이터 유실 발생. **다음 실행 전 최우선.**
2. **T19(검토 결함 수정: vhost --domain / dir 스키마 / scope 주석)**.
3. **T20(자가개선 메커니즘 + 로그)** — 이후 모든 실행이 이 절차를 따르므로 조기 도입.
4. (Phase 2 미완이 있으면) T9→T10→T11+T12→T15→T13→T16+T17→T14 순.

각 태스크 완료 시 [README.md](README.md) "구현 상태" 표와 [TASK-RESULT.md](TASK-RESULT.md)를 갱신할 것.

---

# Phase 4 — JS 딥 디오브푸스케이션 + 임베디드 정보 추출 (T21)

### T21. 난독화 JS 심층 해석으로 숨은 정보 수집 (우선순위 1)

**목적**: 인코딩·난독화로 숨겨진 정보(엔드포인트·시크릿·버전·경로·주석)를 드러내 수집한다.

**왜 (현재 공백)**: 현재 `normalize_js.py`는 **charset 디코딩 + eval-packer(p,a,c,k,e,d) 1종 + beautify**
까지만이다. 요즘 흔한 **string-array 난독화**(javascript-obfuscator: 배열+rotate+base64/RC4,
control-flow flattening), JS 문자열에 숨긴 **인코딩 블롭**(base64/hex/`\xNN`/`\uNNNN`/URL-encoded),
그리고 **source map**을 활용하지 못한다. 결과적으로 "버전·엔드포인트를 숨긴" 타깃(강사가 경고한 시나리오)의
정보를 놓친다. 이 태스크는 기존 파이프라인의 normalize 단계를 **심화**한다(재작성 아님).

**접근**:
1. **난독화 유형 탐지 → 매칭 디코더 라우팅** (`scripts/deobfuscate.py` 또는 normalize 확장):
   - eval-packer(보유), **javascript-obfuscator string-array 언패커**(배열 복원+rotate 역산+base64/RC4 디코딩),
   - **범용 인코딩 디코더**: 문자열 리터럴의 base64/hex/`\x`/`\u`/URL-encoded 를 **재귀적으로** 디코딩
     (중첩 인코딩 대응, 폭주 방지 상한).
2. **source map 수집·복원**: 수집기(`collect_web`/`collect_spa`)가 `//# sourceMappingURL=`·`.map`도
   fetch 해 manifest 자산으로 등록. `.map`이 있으면 **원본 소스·파일명·경로 복원**(가장 깨끗한 디오브푸스케이션).
3. **디코드본 재분석**: 디코드 산출물을 `captures/decoded/`에 표준 UTF-8 저장·해시하고, 여기에
   `fingerprint.py`(버전 지문)와 `extract_assets.py`(엔드포인트·시크릿·버전) 를 **재적용**해 숨었던 정보를 발견.
4. **환각 통제 (중요)**:
   - 디코드본은 **파생물**이다. 각 산출물에 **어떤 디코더로 어느 원본 자산(asset_id)에서** 나왔는지 기록.
   - finding 근거는 읽을 수 있는 디코드본에 바인딩하되(evidence_path=decoded 파일, 바이트 인용) **원본
     자산 링크를 유지**한다. `asset_sha256`은 디코드 파일에서 재계산(게이트 일치).
   - 디코드는 틀릴 수 있다 → 가능하면 **가역성/일관성 체크**(re-encode 대조)로 뒷받침하고, 불확실하면
     provenance를 낮춘다. 디코드 실패도 Observation 보존(삭제 금지).
   - 시크릿은 마스킹(기존 규율).
5. **경계**: VM기반·완전 커스텀 난독화의 전면 복원은 시도하지 않는다(무한). **흔한 난독화·인코딩·source
   map에 집중**, 못 뚫으면 `unknown`으로 보존(억지 복원 금지).

**설치**: string-array 언패킹은 성숙 도구 통합 권장(예: `webcrack`/`synchrony` 같은 디오브푸스케이터를
Docker 이미지에 고정, checksum). 통합 시 출력은 디코드본으로 저장 후 우리 파이프라인이 재분석.

**완료 기준**: 유형별 픽스처(eval-packer / string-array / base64·hex 블롭 / source map)에서 숨은
**엔드포인트·버전**이 디코드 후 발견되고 게이트 GO. 디코더·원본 추적이 기록되고, 디코드 실패는 unknown 보존.

**환각 통제**: 디코드본 파생물 표기 + 원본 링크 + 해시 재검증, 가역성 체크로 오디코드 억제, 시크릿 마스킹.

---

**권장 순서(갱신)**: Phase 3(T18~T20) 완료 후 → **T21**(숨은 정보 수집, 정찰 가치 큼).

---

# Phase 5 — 경계 방어 탐지 (T22)

### T22. WAF/CDN/IPS/레이트리밋 탐지 — 방어 태세 파악 (우선순위 1)

**목적**: 타깃 앞단에 WAF·CDN·IPS·레이트리밋 등 방어가 있는지 탐지한다. **정찰 강도(얼마나 시끄럽게
스캔할지)를 결정하고, 방어를 건드리기 전에 알게 한다.**

**왜**: 방어 유무를 모르고 능동 스캔하면 차단·탐지되어 **접근을 잃거나 알람을 유발**한다. 방어 지문은
헤더·쿠키·차단 행위에 남는다. 탐지 난이도가 종류마다 다르므로 정직하게 구분한다.

**접근**:
1. **패시브 WAF/CDN 지문 (저위험, 먼저)** — 응답 헤더·쿠키·차단 페이지 마커로 식별. `harness/signatures/
   waf.json`·`cdn.json` **데이터** 추가(T9의 헤더/쿠키 자산 재사용, 스크립트 로직 아님):
   - Cloudflare(`cf-ray`, `__cf_bm`/`cf_clearance` 쿠키, "Attention Required"/challenge 페이지),
     Akamai(`X-Akamai-*`, `AkamaiGHost`, `_abck`/`ak_bmsc` 쿠키), Imperva/Incapsula(`X-Iinfo`, `incap_ses_*`
     `visid_incap_*` 쿠키), F5 BIG-IP(`BIGipServer*`/`TS*` 쿠키, `X-WA-Info`), AWS WAF, ModSecurity
     (`Mod_Security`/`NOYB`), Sucuri(`X-Sucuri-ID/Cache`), Fortinet FortiWeb, Barracuda, Wordfence 등.
   - 고유 마커 존재 = `confirmed`(바이트 인용). 여러 CDN 뒤에 WAF가 겹칠 수 있으니 복수 탐지 허용.
2. **wafw00f 통합** — 성숙 도구를 Docker 이미지에 checksum 고정, 출력을 finding으로 파싱(cariddi 방식).
   순수 파이썬 시그니처 폴백도 제공.
3. **능동 WAF/IPS 행위 프로브 (GO 게이트)** — `active_recon.py --waf-probe`(또는 신규): 무해한 엔드포인트에
   **소량의** 벤치 페이로드(예: `?x=<script>alert(1)`, `../../etc/passwd`, `' OR '1'='1`)를 보내 차단 반응
   (403/406/429/501/챌린지/RST) 관찰 → WAF/IPS 존재 `inferred`. **⚠️ 방어를 건드릴 수 있음**: 반드시
   `GO <recon_id>`+`--approved`, 최소 프로브, **트립(차단 관찰) 시 즉시 중단·사람 보고**.
4. **레이트리밋/IPS 행위** — baseline 대비 N요청 후 차단/드롭(429·연결 리셋·타르피팅) 관찰 → `inferred`.
5. **결과 클래스 분리(invariants 준수)** — transport 실패(RST/timeout) vs 대상의 정상 403/404 vs WAF
   차단 페이지를 **같은 결과로 취급하지 않는다**. 차단 페이지는 마커로 구분.
6. **정직한 경계** — 순수 패시브 **IDS**(아웃오브밴드 탐지 전용)는 대개 **탐지 불가**. 못 잡으면 `unknown`
   으로 두고 지어내지 않는다.
7. **산출** — "방어 태세(defense posture)" finding(예: `asset_kind: "defense"`, product = `waf`/`cdn`/`ips`/
   `ratelimit`, 제품명). 다운스트림 하네스·사람에게 **"스캔 강도 조절" 경고**로 노출. 방어 탐지는 정찰
   초반(패시브)에 돌려 이후 능동 강도를 정하는 입력이 되게 한다.

**설치**: `wafw00f`(pip 또는 바이너리)를 Docker 이미지에 고정.

**완료 기준**: WAF 헤더/쿠키 픽스처에서 `confirmed` 탐지, 능동 프로브는 GO 없이 미실행(STOP), 차단 행위
픽스처에서 `inferred`, IDS는 unknown 보존, 게이트 GO. 회귀 테스트 추가.

**환각 통제**: 고유 마커=confirmed / 행위 추론=inferred / IDS 미탐=unknown, 프로브 응답을 evidence로
바인딩, 능동 프로브는 GO 게이트, 결과 클래스 분리로 오탐 억제.

---

# Phase 6 — WSTG-INFO 커버리지 정합 (T23~T28)

> 근거: OWASP WSTG 4.1 Information Gathering(INFO-01~10)과 본 하네스를 매핑해 공백을 메운다.
> 사설 CTF 랩 대상이라 INFO-01(검색엔진/Shodan)은 "공인 인터넷·제3자 정찰 STOP" 규율과 충돌하므로
> **의도적 제외**다. INFO-06(진입점 전수화)·INFO-07(실행경로)은 **후속 취약점 진단 하네스의 입력**
> 영역이라 이 하네스 범위 판단이 필요하다(아래 T28 참고, 기본은 보류).
>
> **이번 세션 완료(✅) — 다른 에이전트는 재작업 금지, 확장만**:
> - **WSTG-INFO-03 메타파일 패시브 수집**: [collect_web.py](scripts/collect_web.py)에 `METAFILES`
>   상수(robots.txt/sitemap.xml/security.txt/.well-known/security.txt/humans.txt)를 진입 오리진에서
>   고정 목록·1회씩 GET. 존재분만 `asset_kind:"metafile"` 자산으로 등록(sha256), 부재/실패는
>   `captures/observation/metafiles-absent.txt`에 보존. `--skip-metafiles`로 off. `extract_assets.py`의
>   `KINDS`에 `"metafile"` 추가돼 이어서 마이닝됨.
> - **WSTG-INFO-05 개발자 주석·내부 IP 추출**: [extract_assets.py](scripts/extract_assets.py)에
>   `COMMENT_RULES`(html `<!-- -->` / js·css `/* */`), `PRIVATE_IP`(RFC1918+127/8) + `is_private_ipv4()`
>   옥텟·범위 이중검증, `byte_quote()`(게이트와 동일 바이트 재검증 규율, cp949 등 인코딩 불일치 시 실재
>   ASCII 런 폴백). `asset_kind:"comment"`/`"internal-ip"`, 둘 다 존재=`confirmed`·해석=inferred/사람.
>   obs에 `comments`/`internal_ips` 키. 유닛 테스트 `tests/test_python.py`에 추가(30 passed).
>
> ⚠️ **로컬 통합 테스트 사전조건**: `scope.md`가 `UNSET`이면 통합 스위트가 REVISE로 대량 실패한다.
> 실행 전 `허용 대역: 127.0.0.1/8`을 **임시** 설정하고 종료 후 `UNSET`으로 복원할 것(scope.md 주석 지침).
> (참고: T11 Django 해시 테스트는 이 환경에서 기존부터 실패 — 본 세션 변경과 무관.)

---

### T23. 내부 IP 오탐 신뢰도 등급화 (우선순위 2)

**목적**: T25(세션 완료분)의 `internal-ip` 발견을 문맥 기반으로 등급화해 오탐 신호를 낮춘다.

**왜 (현재 한계)**: 지금은 사설 IP 문자열이 **존재하면 무조건 `confirmed(존재)`**. 그러나 semver·예제
상수·vendor 라이브러리에 박힌 IP는 "내부 인프라"가 아닐 수 있다. 존재는 여전히 confirmed지만
"내부 인프라 주소일 가능성"은 등급이 필요하다.

**접근** ([extract_assets.py](scripts/extract_assets.py) internal-ip 블록 확장, 로직 최소·데이터 우선):
- finding에 `confidence`(또는 provenance 보조) 부여: 문맥이 `x.y.z.w/버전`·semver 인접이면 `guess`,
  minified vendor 자산(react-dom 등)이면 `guess`, 그 외 `inferred`. **존재 자체(confirmed)는 유지.**
- **노이즈 allowlist**(데이터): `0.0.0.0`, `127.0.0.1`, `192.168.0.1`, `192.168.1.1` 등 흔한 문서/기본 상수
  → 별도 태그(`ip_noise:true`)로 낮은 신호.
- **타깃 자기참조 제외**: 발견 IP == 스캔 대상 IP면 자명 → 낮은 신호 태그.
- 결과는 report 승격 우선순위에만 영향. 원문·obs는 그대로 보존(삭제 금지).

**완료 기준**: 픽스처(semver 인접 IP / vendor lib IP / 실제 내부 호스트 IP)에서 등급이 갈리고 게이트 GO.
회귀 테스트 추가. 존재=confirmed 규율 불변.

**환각 통제**: 존재는 confirmed 유지, "내부 인프라 여부"만 inferred/guess로 하향. 지어낸 등급 금지(문맥 근거).

---

### T24. 주석 민감도 분류 + 재마스킹 (우선순위 2)

**목적**: T25(세션 완료분)의 `comment` 발견에서 민감정보 누출을 사전 차단하고, 사람 검토 우선순위를 준다.

**왜 (현재 한계)**: 주석 원문 프리픽스가 finding `evidence_quote`에 들어간다. findings.json은
`targets/*`(gitignore·로컬 전용)라 유출 위험은 낮지만, 주석 안 키/비번이 quote로 남을 수 있고 노이즈가 많다.

**접근** ([extract_assets.py](scripts/extract_assets.py) COMMENT 블록 확장):
- **주석 텍스트에 `SECRET_RULES` 재적용**: quote 확정 전 시크릿 패턴이 있으면 마스킹(기존 `mask()` 재사용).
  주석 finding의 evidence_quote에도 이중 마스킹.
- **유형 태깅**(데이터): `TODO`/`FIXME`/`XXX`/`HACK`, `internal-host`(사설 IP·`.local`·`.htb` 포함),
  `credential-ish`(`password`/`api[_-]?key`/`token` 단어), `legacy-endpoint`(`/api`·`.php`·주석처리 경로).
  finding에 `comment_tags` 배열로.
- report_eligible=false 기본 유지. 태그로 사람이 우선순위 판단.

**완료 기준**: 시크릿 심은 주석 픽스처에서 quote가 마스킹되고, 유형 태깅이 정확하며 게이트 GO. 회귀 테스트.

**환각 통제**: 마스킹 규율(쿠키/시크릿과 동일), 태그는 결정론 regex 근거. 존재=confirmed 유지.

---

### T25. sitemap/robots 재귀 파싱 → candidate-paths 관찰물 (수동 파싱/능동 fetch 분리) (우선순위 1)

**목적**: 메타파일이 **선언한 URL·경로**를 재귀로 모아 능동 정찰 후보 목록을 만든다. 단, **모으기(파싱)와
접속(fetch)을 엄격히 분리**한다.

**왜 (오해 방지 — 중요)**: sitemap을 재귀로 풀면 "**사이트가 선언한 URL 전체**"는 나오지만 이는
"**접속 가능한 모든 페이지**"가 아니다. 관리자·내부 API·인증 뒤·동적 라우트는 보통 sitemap에 없고,
sitemap에는 이미 삭제된(404) URL이 남기도 한다. 완전 커버리지는 sitemap(선언) + 링크 크롤(T16) +
**디렉터리 브루트포스(능동)** 를 합쳐야 근접한다. 그리고 **sitemap의 URL을 실제로 fetch하는 것 자체가
능동 행위**다. 따라서 이 태스크는 **관찰물(후보 목록)만 산출**하고 접속은 능동 단계로 넘긴다.

**접근**:
- **파싱 전용(요청 없음)**: 이미 수집된 `asset_kind:"metafile"` 원본(robots.txt/sitemap.xml)에서
  - robots.txt의 `Disallow`/`Allow` 경로, sitemap의 `<loc>` URL, **`<sitemapindex>` 중첩 사이트맵을
    재귀 파싱**(단, 중첩 sitemap이 **아직 수집 안 된 별도 URL이면 fetch하지 않고** "미수집 후보"로 표기 —
    수집은 T16 크롤 또는 능동 단계에서). 재귀 폭주 방지 상한.
  - 산출: `targets/<host>/captures/observation/candidate-paths.txt`(경로·URL·출처 메타파일 태그).
    이는 **관찰물**이지 finding이 아니다(접속 미확인이므로 존재 단정 불가).
- **능동 연결**: [active_recon.py](scripts/active_recon.py)가 `--candidate-paths <file>`로 이 목록을
  입력받아 **`GO <recon_id>`+`--approved`+스코프 게이트** 하에 접속·발견 기록. 대역 밖 URL은 STOP(미접속).
- robots `Disallow` 경로는 **단서일 뿐** — 자동 추종 금지, 반드시 능동 단계 경유.

**완료 기준**: robots/sitemap(+중첩) 픽스처에서 candidate-paths.txt가 요청 없이 생성되고, 능동 단계가
GO 승인 시에만 그 목록을 접속한다. 대역 밖 후보 미접속(STOP). 회귀 테스트.

**환각 통제**: 파싱=관찰물(존재 단정 아님), 접속 후에만 finding. 수동/능동 경계 유지, 대역 게이트 준수.

---

### T26. security.txt 연락처(PII) 마스킹 (우선순위 3)

**목적**: security.txt의 연락 이메일 등 PII를 finding/report에서 마스킹한다(산출물 위생).

**접근**: `asset_kind:"metafile"` 중 security.txt에서 `Contact:` 이메일을 추출하면 `a***@domain` 마스킹
형태로만 finding에 두고, 원문은 gitignore 대상 raw에만. (공개 목적 파일이라 위험은 낮으나 규율 일관성.)

**완료 기준**: security.txt 픽스처에서 이메일이 마스킹되어 노출되고 게이트 GO. 회귀 테스트.

**환각 통제**: 시크릿/쿠키와 동일 마스킹 규율.

---

### T27. 수동/"semi-passive" 경계 명문화 (⚠️ 신뢰 앵커 수정 — 사람 승인 필수)

**목적**: 메타파일 수집(T-세션분)처럼 "브라우저가 자동으로 보내지 않는 표준 well-known 파일의 단발 GET"을
어느 강도로 분류할지 계약에 명시한다.

**⚠️ 자가수정 금지**: 이 태스크는 [AGENTS.md](AGENTS.md)·[invariants.md](harness/policies/invariants.md)
= **신뢰 앵커** 수정을 포함한다. 코딩 에이전트는 **직접 고치지 말고**, 변경 초안을 **사람에게 제안**한 뒤
승인받아 반영한다(self-repair 가드레일 규율과 동일).

**접근(제안 초안)**:
- 수동/능동 2분류에 **"semi-passive"**(표준 well-known 파일 고정 목록·오리진 한정·단발 GET) 티어를 정의할지
  검토. 메타파일 수집이 여기 속함을 명시.
- manifest에 **총 요청 수(request budget)**를 기록해 "수동이라는데 요청이 몇 건인가"를 감사 가능하게(이건
  신뢰 앵커 아님 — 수집기 변경으로 먼저 가능).
- 결론이 "메타파일도 GO 필요"로 나면 collect_web의 `METAFILES` 수집을 게이트 뒤로 이동.

**완료 기준**: 사람 승인된 경계 정의가 AGENTS/invariants에 반영되고, 코드(수집기 기본 동작)가 그 정의와
일치. request budget이 manifest에 기록되고 회귀 테스트.

---

### T28. 잔여 WSTG 공백 — favicon 해시(INFO-09)·인프라 헤더(INFO-10)·진입점(INFO-06) (우선순위 3)

**목적**: 남은 WSTG 항목을 데이터 우선으로 보강하되, 실데이터가 필요한 것은 정직하게 소싱한다.

**접근**:
- **INFO-09 favicon 해시 매칭**: favicon은 이미 `asset_kind:"favicon"`로 수집된다. mmh3(Shodan 방식:
  base64(body)→murmur3) 또는 sha256을 계산해 `harness/signatures/maps/favicon-hashes.json`(해시→제품)로
  매칭. **⚠️ 핵심 규율**: 해시 DB 값은 **실제 제품 favicon에서 계산해 채운다(출처 기록)** — "CVE는 기억이
  아니라 조회로"와 동일하게, **LLM 기억으로 해시를 지어내지 않는다**. 초기엔 소량 실측치로 시작.
- **INFO-10 인프라 헤더 시그니처**(데이터): `Via`/`X-Cache`/`X-Forwarded-*`/`X-Served-By`/`Server-Timing`
  등을 `harness/signatures/*.json`에 헤더 매칭(T9 substrate 재사용)으로 추가 → 리버스프록시·캐시·LB 계층
  `inferred`. 스크립트 로직 변경 없이 데이터로.
- **INFO-06 진입점(보류 판단)**: form/input/GET·POST 파라미터/GraphQL 입력 벡터 목록화는 **후속 취약점
  진단 하네스의 입력**일 수 있다. 착수 전 **범위 결정**(이 하네스가 할지 위임할지)을 사람과 확정. 하기로
  하면 collect 단계에서 `<form>`·`<input>`·쿼리스트링을 구조화해 관찰물로만(공격 아님).

**완료 기준**: favicon 해시 매칭이 실측 DB로 제품 confirmed(자산 해시 일치), 인프라 헤더가 근거와 함께
inferred, 게이트 GO. favicon DB 출처 문서화. INFO-06은 범위 결정 기록.

**환각 통제**: favicon 해시는 실측 자산 기반(confirmed), 인프라 헤더는 마커 존재=confirmed/계층 해석
=inferred. **해시 DB 날조 금지**(외부 실측만).

---

**권장 순서(Phase 6)**: T25(sitemap 후보 파싱 — 정찰 가치 큼) → T23·T24(오탐/민감도 위생) →
T26 → T28(데이터 보강) → T27(경계 명문화, 사람 승인 대기). 각 완료 시 [README.md](README.md) "구현 상태"
표와 [TASK-RESULT.md](TASK-RESULT.md)를 갱신할 것.
