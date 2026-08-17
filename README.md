# External Recon Harness (외부 정찰 하네스)

대규모 다중 플래그 엔터프라이즈 랩(HTB ProLabs / Fortresses **스타일**) CTF의 **외부 정찰** 하네스.
외부 공격 표면(웹 자산·헤더·쿠키·포트·vhost·서브도메인·공개 AWS)만 다룬다. 발판 확보 후의 내부
정찰·포스트익스플로잇은 별도 하네스가 맡는다.
HTB 자체가 아니라 그 스타일의 CTF이며, 실제 환경·네트워크 접근 방식·허용 대역은 **CTF 당일 공개**된다.
이 하네스는 그 전에 미리 만들어 두고 당일 `scope.md`와 실행 프로파일만 채워 바로 쓰도록 설계했다.
웹 자산(HTTP 헤더·JS·CSS·쿠키·파비콘)을 근거로 "이 타깃이 무슨 제품 무슨 버전인가"를
**검증 가능한 근거와 함께** 산출한다. CVE 매핑·익스플로잇은 별도 하네스로 위임한다.

[cj-aisecurity-harness](../cj-aisecurity-harness)의 증거 규율("AI 출력은 Evidence가 아니다")과
게이트(해시 재계산·근거 재검증·STOP 분류)를 정찰용으로 이식했다.

---

## 설계 원칙 (환각 통제)

| 통제 | 구현 |
|---|---|
| 증거 바인딩 | 버전 단정엔 `evidence_path`(실재 파일) + `evidence_quote`(파일 부분 문자열) + `asset_sha256`(재계산 일치) 필수 |
| 출처 등급 강제 | `provenance`: `confirmed` / `inferred` / `guess` / `unknown`. AI는 `confirmed` 자가 승격 불가 |
| 결정론적 우선 | 수집·정규화·매칭은 스크립트가, AI는 미매칭 자산 추론만 |
| "모름" 1급 출력 | `unknown`은 정식 값. 판단 불가가 정답이면 그걸 뱉는 게 성공 |
| CVE는 조회로 | 이 하네스는 제품·버전까지만. CVE는 매핑 하네스가 외부 조회로 |
| 결정론적 게이트 | `npm run check` → GO / REVISE / **STOP**(스코프 위반) |

상세: [AGENTS.md](AGENTS.md) · [harness/policies/invariants.md](harness/policies/invariants.md)

---

## 파이프라인

```
Passive Collect → Normalize → Fingerprint(결정론) → AI Inference(fallback) → [GO] Active Recon → Verify → Report
```

### 1. 타깃 워크스페이스 생성
```bash
node scripts/new-target.mjs 10.10.110.5
```

### 2. 수동 수집 (헤더/JS/CSS/쿠키/파비콘)

정적(의존성 없음):
```bash
python scripts/collect_web.py http://10.10.110.5/ --target 10.10.110.5
```

SPA(동적 — 런타임 청크·XHR·렌더 DOM까지). `pip install playwright && playwright install chromium` 필요:
```bash
python scripts/collect_spa.py http://10.10.110.5/ --target 10.10.110.5
```
SPA는 빈 껍데기 HTML을 주므로 정적 수집으론 지문 대부분을 놓친다 → SPA 의심 시 이걸 쓴다.

→ 두 수집기 모두 `targets/<host>/captures/raw/` 에 원본, `captures/manifest.json` 에 `asset_sha256`.
이후 3~8단계(normalize/fingerprint/fallback/second-pass/active/gate)는 수집 방식과 무관하게 동일하다.

**vhost** (같은 IP, 다른 가상호스트를 독립 타깃으로):
```bash
python scripts/collect_spa.py http://intranet.corp.htb/ --target intranet.corp.htb --host-map intranet.corp.htb=10.10.110.5
python scripts/collect_web.py http://10.10.110.5/ --target dev.corp.htb --host dev.corp.htb
```
vhost 발견(Host 브루트포스)은 능동 정찰이며 `GO` 뒤 수행한다.

### 3. JS 정규화 (지문 추출용)
```bash
python scripts/normalize_js.py 10.10.110.5
```
난독화/패킹 JS를 beautify·언패킹. `pip install jsbeautifier` 하면 정규화 정확도가 오른다.

### 4. 결정론적 핑거프린팅
```bash
python scripts/fingerprint.py 10.10.110.5
```
→ `targets/<host>/findings.json`. 매칭 실패 자산은 `unmatched`로 보존(AI fallback 입력).

### 5. AI fallback 추론 (결정론 매칭 실패 자산)
```bash
# 서브에이전트가 harness/prompts/fallback-inference.md 계약대로 판정 JSON 을 낸 뒤:
python scripts/merge_fallback.py 10.10.110.5 judgments.json
```
판정이 `unknown` 이면 `unmatched` 에 그대로 보존된다(삭제 금지). 지어낸 인용은
병합 전 바이트 검증과 게이트가 REVISE 로 잡는다.

### 6. 2차 재검증 (고가치 발견)
```bash
python scripts/second_pass.py 10.10.110.5 --prepare        # 증거만 뽑아 입력 생성(맥락 제거)
python scripts/second_pass.py 10.10.110.5 --apply verdicts.json
```
`contradict` 판정이 나오면 `confirmed` 는 `inferred` 로 자동 강등된다.

### 7. 능동 정찰 (RUN — `GO <recon_id>` 승인 필수)
```bash
# vhost 발견 (Host 브루트포스, baseline 대조로 오탐 억제)
python scripts/discover_vhost.py 10.10.110.5 --target 10.10.110.5 --recon-id RECON-01 --approved
# 포트/서비스 스캔 + 디렉터리 열거 (nmap/gobuster)
python scripts/active_recon.py 10.10.110.5 --target 10.10.110.5 --recon-id RECON-02 --approved --dir-enum
```
`--approved` 없이는 어떤 요청도 보내지 않는다(STOP). 발견된 vhost 는 사람이 확인 후
`--host-map`/`--host` 수집기로 독립 타깃 재수집한다.

### 8. 게이트 확인
```bash
npm run check -- 10.10.110.5
```
- `DECISION=GO` — 근거·해시·인용 무결성 통과
- `DECISION=REVISE` — 누락/미검증 (근거 없는 confirmed, 해시 불일치, 인용 조작 등)
- `DECISION=STOP` — 타깃이 `scope.md` 허용 대역 밖

---

## Docker 실행 (권장 — T1)

재현성·격리·검증 이중화를 위해 정찰 도구 환경을 이미지에 고정한다. 컨테이너는 **수집·실행만**,
검증(해시·인용 재계산)은 **호스트 게이트**가 독립 수행한다.

**장수(long-lived) 컨테이너 + `docker exec` 모델** — 명령마다 재시작하지 않는다:

```bash
# 1) 빌드(이미지 digest 를 compose.yaml 에 고정):
docker build -t recon-harness -f docker/Dockerfile .
docker images --no-trunc --format '{{.ID}}' recon-harness   # → sha256 digest
#    docker/compose.yaml 의 image: recon-harness@sha256:<digest> 기록

# 2) 세션 시작(한 번):
docker compose -f docker/compose.yaml up -d

# 3) 각 명령은 래퍼로 투입(없으면 up -d, 실행 후 manifest 에 runtime_image_digest 기록):
node scripts/recon.mjs --target 10.10.110.5 python scripts/collect_web.py http://10.10.110.5/ --target 10.10.110.5
node scripts/recon.mjs python scripts/normalize_js.py 10.10.110.5
node scripts/recon.mjs python scripts/fingerprint.py 10.10.110.5
node scripts/recon.mjs nmap -sV -p- 10.10.110.5

# 4) 세션 종료(Cleanup):
docker compose -f docker/compose.yaml down
```

- 결과는 `./targets:/work/targets` 마운트로 실시간 로컬 저장. 게이트는 호스트에서 실행한다.
- `runtime_image_digest` 는 실행 중 컨테이너의 실제 이미지(태그 재조회 아님)에서 읽어 manifest 에 기록한다.
- **로컬 직접 실행 폴백 유지**: Docker 를 안 써도 기존 `python scripts/...` 경로가 그대로 동작한다.

> ⚠️ **Windows Docker Desktop 루프백 주의**: 컨테이너 안의 `localhost` 는 컨테이너 자신이다.
> 호스트의 로컬 웹 서버를 수집하려면 `http://host.docker.internal:<port>/` 를 쓴다.
> (테스트 픽스처 `tests/fixtures/www` + `python -m http.server 8910` 가 그 예시다.)
> 네트워크 접근 방식(VPN 등)은 CTF 당일 확정 후 `docker/compose.yaml` 의 접근 프로파일로 교체한다.

---

## 사람이 개입하는 구간

| 구간 | 시점 | 행동 |
|------|------|------|
| Scope 설정 | 시작 시 | `scope.md` 허용 대역을 CTF가 지정한 대역으로 갱신 |
| 능동 정찰 승인 | 수동 정찰 후 | 채팅에 `GO <recon_id>` |
| confirmed 판정 | 핑거프린트 후 | 결정론적 매칭/재검증 근거 확인 |
| report_eligible | 확정 전 | 보고서에 넣을 발견 승인 |

`진행해`·`알아서 해`는 능동 정찰 승인이 아니다.

---

## 의존성

- **컨테이너 실행(권장)**: `docker/Dockerfile` 에 전부 고정(nmap·gobuster·playwright·jsbeautifier).
- **로컬 직접 실행(폴백)**: `pip install -r requirements.txt` + `playwright install chromium`.
  node는 스크립트 실행에 필요(게이트·래퍼·워크스페이스 생성).
- 테스트: `npm test` (게이트/파이프라인 회귀 + 파이썬 유닛).

---

## 구조

```
.
├── AGENTS.md / CLAUDE.md          # 공통 계약 + 어댑터
├── scope.md                       # 허용 대역 (Gate가 읽음)
├── requirements.txt               # 로컬 폴백용 파이썬 의존성
├── wordlists/                     # 능동 정찰 워드리스트(컨테이너에 마운트)
├── harness/
│   ├── workflow.md                # PLAN→GO→RUN→CHECK
│   ├── policies/invariants.md     # 증거 바인딩·provenance 규율
│   ├── prompts/                   # 서브에이전트 작업 계약
│   │   ├── fallback-inference.md  #   AI fallback 추론 (unmatched 자산)
│   │   └── second-pass-verify.md  #   2차 재검증 (맥락 제거 재판정)
│   ├── signatures/*.json          # 제품·버전 규칙(데이터)
│   ├── signatures/maps/           # 버전 매핑/해시 DB(데이터)
│   │   ├── werkzeug-flask.json    #   Werkzeug 버전 → Flask 릴리스 시기
│   │   └── django-static-hashes.json  # Django admin 정적 자산 해시 → 버전
│   └── templates/                 # finding.json, asset.json, report.md
├── scripts/
│   ├── collect_web.py             # 수동 수집 + --depth 크롤(T16) + --host vhost
│   ├── collect_spa.py             # SPA 동적 수집 + --host-map vhost=ip
│   ├── normalize_js.py            # beautify + 패커 언패킹
│   ├── fingerprint.py             # 결정론 매칭 + 헤더/쿠키 자산 + 매핑/해시 DB(T9~T11)
│   ├── extract_assets.py          # 시크릿·엔드포인트·에러버전 추출(cariddi 통합) (T15)
│   ├── deobfuscate.py             # 난독화 JS 심층 해석(eval-packer/string-array/인코딩/source map) (T21)
│   ├── waf_recon.py               # 방어 태세 탐지(WAF/IPS/레이트리밋, 능동·GO) (T22)
│   ├── merge_fallback.py          # AI fallback 판정 병합/업그레이드 (T2)
│   ├── second_pass.py             # 2차 재검증 러너 (T3)
│   ├── discover_vhost.py          # vhost 발견 (능동·GO 게이트) (T4)
│   ├── active_recon.py            # nmap/디렉터리/서버 프로브 (능동·GO·스코프 게이트) (T5·T12)
│   ├── discover_dns.py            # 서브도메인·DNS 발견 (passive + 능동·GO) (T17)
│   ├── aws_recon.py               # AWS 인프라 정찰 (S3 공개·메타데이터 신호) (T14)
│   ├── build_django_hash_db.py    # Django 정적 해시 DB 구축(공식 릴리스) (T11)
│   ├── lib/self_repair.py         # 자가개선 메커니즘(variants·가드레일·로그·검증) (T20)
│   ├── variants/                  # 자가개선 사본 디렉터리(원본 불변, produced_by 기록)
│   ├── recon.mjs                  # Docker exec 래퍼 (T1)
│   ├── new-target.mjs             # 워크스페이스 생성
│   ├── check-recon.mjs            # 게이트
│   └── lib/checks.mjs             # 게이트 로직(해시·인용 재검증, CIDR STOP)
├── docker/
│   ├── Dockerfile                 # 도구 고정 이미지 (base digest 고정, nmap/gobuster/cariddi)
│   └── compose.yaml               # 장수 컨테이너 + targets/scope/wordlists 마운트 (@sha256 고정)
├── targets/<host>/                # captures/(raw·normalized·decoded·observation), findings.json, report.md
```

- `captures/decoded/` — 디오브푸스케이션 파생물(T21). 각 자산은 `derived_from`(원본 asset_id)+`decoder` 기록.
- 수집기는 JS 의 `//# sourceMappingURL=` 을 따라 `.map` 을 `sourcemap` 자산으로 등록한다.

## 새 제품 지원 추가

`harness/signatures/`에 JSON 규칙을 추가한다(스크립트 수정 불필요).
스키마: [harness/signatures/README.md](harness/signatures/README.md).
- 응답 헤더/쿠키 지문은 `asset_kinds: ["header"]`/`["cookie"]` 로 추가한다(T9 substrate).
- 버전 매핑/해시 DB는 `harness/signatures/maps/` 의 데이터로 추가한다(T11).

## 구현 상태

| 기능 | 상태 |
|------|------|
| 정적 수집 · 정규화 · 결정론 핑거프린트 · 게이트 | ✅ 동작 |
| 인코딩 견고성(CP949/BOM 바이트 기준 대조) | ✅ 동작 |
| SPA 동적 수집(playwright) — 런타임 fiber 지문 캡처 포함 | ✅ 동작 |
| vhost 수집(`--host` / `--host-map`) | ✅ 동작 |
| Docker 실행 환경 (이미지 @sha256 고정 + recon.mjs 래퍼) | ✅ 동작 (T1) |
| AI fallback 추론 — 계약 + 병합/업그레이드 + 게이트 안전망 | ✅ 동작 (T2) |
| 2차 재검증 러너 (verified_by second-pass, contradict 강등) | ✅ 동작 (T3) |
| vhost 발견 러너 (능동·GO·baseline 대조) | ✅ 동작 (T4) |
| 능동 정찰 러너 (nmap 배너 + 디렉터리 + 서버 프로브) | ✅ 동작 (T5·T12) |
| 시그니처 DB (React/jQuery/Angular/Vue/Next/WordPress/nginx/Apache/PHP/Laravel/Flask/Django/Werkzeug) | ✅ 동작 (T6·T10) |
| **헤더·쿠키 1급 매칭 자산 (정적·SPA)** | ✅ 동작 (T9) |
| **버전 범위/해시 DB (Werkzeug→Flask, Django admin 해시)** | ✅ 동작 (T11) |
| **자산 추출 (시크릿 마스킹·엔드포인트·에러버전, cariddi 통합)** | ✅ 동작 (T15) |
| **메타파일 패시브 수집 (robots/sitemap/security.txt/humans, WSTG-INFO-03)** | ✅ 동작 |
| **주석·내부IP 추출 (개발자 주석·RFC1918/루프백, WSTG-INFO-05)** | ✅ 동작 |
| 스코프 제한 크롤 (`--depth N`, 외부 미크롤) | ✅ 동작 (T16) |
| 서브도메인·DNS 발견 (passive + 능동·GO) | ✅ 동작 (T17) |
| AWS 인프라 정찰 (S3 공개·메타데이터 신호) | ✅ 동작 (T14) |
| **fingerprint 멱등 병합 (능동/fallback 결과 유실 방지)** | ✅ 동작 (T18) |
| 검토 결함 수정 (vhost `--domain`/dir 스키마/scope 주석) | ✅ 동작 (T19) |
| 스크립트 자가개선(self-repair) 메커니즘 + 로그 | ✅ 동작 (T20) |
| JS 딥 디오브푸스케이션 (string-array·인코딩블롭·source map) + 임베디드 정보 추출 | ✅ 동작 (T21) |
| 경계 방어 탐지 (WAF/CDN 패시브·IPS/레이트리밋 능동·IDS unknown) | ✅ 동작 (T22) |
| 운영 보강 (워드리스트 마운트, 배너 파싱 정밀화) | ✅ 동작 (T13) |
| 내부 IP 문맥 신뢰도·노이즈 태깅 | ✅ 동작 (T23) |
| 주석 민감도 태깅·안전 인용·security.txt 연락처 마스킹 | ✅ 동작 (T24·T26) |
| robots/sitemap 후보 파싱 + GO-gated fetch | ✅ 동작 (T25) |
| 인프라 헤더 지문(Via/X-Cache/X-Forwarded/Server-Timing) | ✅ 동작 (T28) |
| favicon 해시 DB | ⏸ 실측 제품 자산 소싱 대기 (T28) |
| INFO-06 진입점 목록화 | ⏸ 범위 결정 대기 (T28) |
| semi-passive 경계 신뢰 앵커 반영 | ⏸ 사람 승인 대기 (T27) |
| 라이브 SPA 검증 + 의존성 고정 (requirements.txt) | ✅ 동작 (T7) |
| 테스트·회귀 방지 (`npm test`) | ✅ 동작 (T8) |

## 운영 메모 (T13)

- **워드리스트**: `wordlists/` 를 컨테이너에 마운트한다. 컨테이너의 gobuster 기본 경로는 없으므로
  `--wordlist wordlists/...`/`--dir-wordlist wordlists/...` **지정이 필수**.
- **merge_fallback exit 1**: 판정 중 일부가 거부(미매칭 asset_id, fabricated 등)되면 exit 1.
  유효 병합과 공존해도 실패로 보이므로 **exit 1 = "일부 판정 검토 필요"** 로 해석(거부 사유는 stdout).
- **HTTPS vhost**: 파이썬 폴백은 SNI 를 못 보내므로 https 는 gobuster vhost(컨테이너) 권장.
- **세션 Cleanup**: 통합 테스트가 중단되면 `targets/it-<ts>` 가 남을 수 있다. 종료 시
  `docker compose down` + 잔여 테스트 타깃 제거.
- **AWS 공인 접근**: `aws_recon.py --s3-buckets` 는 공인 AWS 엔드포인트를 건드리므로
  `--approved-for-public`(사람 허용) 필수. CTF 허용 범위만.
> Phase 6의 T27(semi-passive 정책)과 T28의 favicon/INFO-06은 사람 결정 또는 실측 자산이 필요한
> 항목이라 자동 완료하지 않는다. 상세 지시는 [TASK.md](TASK.md)를 참조한다.
