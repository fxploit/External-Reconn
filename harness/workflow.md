# External Recon Harness Workflow (외부 정찰)

Target Intake → Passive Collect → Normalize → Fingerprint (deterministic) → AI Inference (fallback) → Human GO (능동) → Active Recon → Second-Pass Verify → Findings → Report

각 단계는 FACT / INFERENCE / UNKNOWN을 구분한다. 보완 가능한 누락은 REVISE, Scope 위반은 STOP.

> **횡단 규칙 — 스크립트 자가개선**: 어느 단계에서든 수집기·도구 래퍼가 현장에서 깨지면 원본을 보존한
> 채 사본을 자가개선하고 기록한다. 단 검증기(게이트)·계약은 절대 자가수정 금지(STOP→사람 보고).
> 절차: [policies/self-repair.md](policies/self-repair.md).

## Stage Labels

- **PLAN**: Target Intake → Passive Collect → Normalize → Fingerprint → AI Inference
- **HUMAN GO**: 능동 정찰 승인 (`GO <recon_id>`)
- **RUN**: Active Recon (포트/디렉터리/vhost/프로브)
- **CHECK**: Second-Pass Verify → Findings 확정 → Report

## PLAN — 수동 정찰 (저위험, 자동 진행 가능)

수동 수집은 페이지 접속으로 자연히 오가는 것만 다룬다. 타깃 상태를 바꾸지 않으므로 능동 GO 없이 진행하되, 결과는 항상 Observation으로 보존한다.

1. **Passive Collect** — 두 수집기 모두 동일한 `manifest.json` 스키마로 출력한다(다운스트림 재사용).
   - 정적: `python scripts/collect_web.py <url> --target <host>`
     HTTP 헤더 + HTML + 참조된 JS/CSS + 쿠키 + 파비콘. 의존성 없음. 저위험.
   - **SPA(동적)**: `python scripts/collect_spa.py <url> --target <host>`
     헤드리스 Chromium으로 페이지를 실행해 런타임 로드 청크(chunk-*.js)·XHR·쿠키·렌더 DOM까지 캡처.
     SPA는 빈 껍데기 HTML을 주므로 정적 수집으로는 지문 대부분을 놓친다 → SPA로 의심되면 이걸 쓴다.
     의존성: `pip install playwright && playwright install chromium`.
   각 자산의 `asset_sha256`을 `captures/manifest.json`에 기록한다(결정론적 수집).

   **vhost 대응**: 같은 IP가 Host 헤더로 여러 가상호스트를 서빙하면 각 vhost를 독립 타깃으로 수집한다.
   - SPA: `--host-map vhost=ip` (Chromium `--host-resolver-rules`로 Host/TLS SNI를 올바르게)
   - 정적: `--host vhost` (URL은 IP, Host 헤더만 덮어씀; 평문 HTTP)
   - vhost **발견**(Host 브루트포스)은 능동 정찰이며 RUN 단계에서 `GO` 뒤 수행한다(아래 RUN 참고).
2. **Normalize** — `python scripts/normalize_js.py <host>`
   난독화 JS를 beautify하고 흔한 패커(eval-packed p,a,c,k,e,r / 단순 webpack)를 언패킹한다.
   **목표는 복호화가 아니라 지문 추출용 정규화다.** 산출물은 `captures/normalized/`에 둔다.
3. **Fingerprint (deterministic)** — `python scripts/fingerprint.py <host>`
   `harness/signatures/*.json` 규칙으로 제품·버전을 매칭한다.
   원본 문자열 직접 존재/해시 일치 → `provenance: confirmed` 후보.
   매칭 실패한 자산은 `unmatched`로 남긴다(삭제 금지).
4. **AI Inference (fallback)** — 결정론적으로 매칭 안 된 `unmatched` 자산에 한해 AI가 코드 패턴을 읽고 추론한다.
   결과는 반드시 `provenance: inferred` 또는 `guess`. 근거 자산을 인용하되 단정하지 않는다.
   판단 불가는 `unknown`으로 남기는 게 성공이다.
   - 계약: `harness/prompts/fallback-inference.md` (제품/버전은 자산에서 바이트 그대로 인용 가능할 때만).
   - 러너: `scripts/merge_fallback.py` — 판정 JSON 을 받아 `inferred`/`guess` 로 병합(기존 `unknown` 발견
     업그레이드), `unknown` 은 unmatched 에 유지. 지어낸 인용은 병합 전 바이트 검증으로 거부.
   - 병합 후 게이트 재실행: `evidence_quote` 바이트 재검증이 지어낸 인용을 REVISE 로 잡는다(안전망).

수동 단계 산출물은 전부 `findings.json` 초안에 `provenance`와 함께 기록한다.

## HUMAN GO — 능동 정찰 승인

능동 정찰(RUN) 실행 전에 `recon_id`, 목적, 명령, Target, 예상 부하, 성공/실패 관찰, Cleanup을 표시하고
`GO <recon_id>`를 기다린다. 도구 파일·명령 초안은 GO 이전에 AI가 작성할 수 있으나, 실행은 GO 뒤에만 한다.

## RUN — 능동 정찰

- 포트/서비스 스캔, 디렉터리 열거, 배너 그래빙, 취약점 프로브.
- **vhost 발견**: Host 헤더를 워드리스트로 브루트해 응답 차이로 숨은 가상호스트를 찾는다.
  발견된 vhost는 각각 PLAN의 수집기(`--host-map`/`--host`)로 독립 타깃으로 다시 수집한다.
- 러너(`scripts/discover_vhost.py`, `scripts/active_recon.py`)는 **도구 수준 GO 게이트**가 있다:
  `--recon-id` + `--approved` 없이는 어떤 요청도 보내지 않으며, 타깃 IP가 `scope.md` 허용 대역
  밖이면 요청 전에 STOP한다(대역 밖 관찰 시 즉시 STOP·자동 확장 금지).
- 각 실행은 stdout/stderr/exit code/명령/타임스탬프를 `captures/observation/` 에 보존하고,
  도구 원본 출력(배너 등)은 `confirmed` 후보로 findings 에 바인딩한다.
- 허용 대역 밖 타깃이 관찰되면 즉시 STOP하고 사람에게 보고한다(랩 내부 피벗 대상일 수 있으므로 자동 확장 금지).

## CHECK — 재검증 · 확정 · 보고

1. **Second-Pass Verify** — `confirmed`로 승격되거나 다음 하네스로 넘어갈 고위험 발견은
   원본 증거만 주고 맥락 없이 재판정한다. 두 판정이 갈리면 자동 등급 강등.
2. **Findings 확정** — 사람이 검토해 `report_eligible`을 정한다. AI가 자가 확정하지 않는다.
3. **Report** — `report.md`에 발견을 provenance 등급별로 표기하고, 각 FACT는 `[asset:REF]`를 인용한다.

## 표준 출력 계약

모든 발견은 `harness/templates/finding.json` 스키마를 따른다. 이 파일이 하네스 간 인터페이스다.
CVE 매핑 하네스는 `provenance: confirmed`인 (product, version)만 자동 진행하고 그 이하는 재검증을 요구한다.
