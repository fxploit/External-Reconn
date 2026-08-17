# External Recon Harness (외부 정찰 하네스) — 공통 AI Agent 계약

**AI 출력은 Evidence가 아니다. 핑거프린트는 Observation이 근거이고, 버전 단정은 원본 자산이 근거다.**

이 하네스는 대규모 다중 플래그 엔터프라이즈 랩(HTB ProLabs / Fortresses **스타일**)의 CTF **외부 정찰(External Recon)** 단계를 담당한다.
**외부 공격 표면만 다룬다**: 웹 자산·응답 헤더·쿠키·포트/서비스·vhost·서브도메인/DNS·공개 AWS 리소스.
발판 확보 뒤의 **내부 정찰(내부망 스캔·AD 열거·피벗·포스트익스플로잇)은 이 하네스의 범위가 아니며 별도 하네스**가 담당한다.
HTB 자체가 아니라 그 스타일의 CTF이며, 실제 환경·네트워크 접근 방식·허용 대역은 **CTF 당일 공개**된다(현재 미정).
따라서 특정 접속 방식(VPN 등)이나 대역을 하드코딩하지 말고, `scope.md`와 실행 프로파일로 교체 가능하게 둔다.
목표는 "이 타깃이 무슨 제품 무슨 버전인가"를 **검증 가능한 근거와 함께** 산출하는 것이다.
CVE 매핑·무기화·익스플로잇은 이 하네스의 범위가 아니며 별도 하네스로 위임한다.

## 오케스트레이션 상 위치

Claude Code(오케스트레이터)가 정찰 국면에서 이 하네스를 서브에이전트에 위임한다.
서브에이전트는 **콜드 스타트**다(이전 컨텍스트를 물려받지 않는다). 따라서:

- 모든 발견은 `targets/<host>/findings.json`에 **파일로 영속화**한다. 에이전트 메모리에 의존하지 않는다.
- 다음 하네스(CVE 매핑 등)는 이 파일을 입력으로 받는다. 출력 스키마(`harness/templates/finding.json`)는 계약이다.

## 시작

`RECON START <target>` 를 받으면 README, scope.md, 대상 워크스페이스, Git 상태를 먼저 읽는다.

**Preflight** (매 START마다):

- 이 작업 디렉터리가 사용자가 받은 사본인지 확인한다.
- `git status`로 미커밋 변경·이전 세션 잔여물을 확인한다.
- 타깃이 `scope.md`의 허용 대역 안인지 확인한다. **밖이면 STOP.**
- 현재 모델·effort·permission 모드가 이번 작업에 맞는지 확인한다.

첫 응답에서 성공 기준과 범위를 1~2개 질문한다. 사용자 답변 전에는 능동 스캔을 실행하지 않는다.

## 수동(Passive) vs 능동(Active) 정찰

- **수동**: 페이지 접속으로 자연히 오가는 것 — HTTP 헤더, HTML, JS/CSS, 쿠키, 파비콘, 정적 자산, 그 응답의 네트워크 로그. 저위험. 자동 진행 가능하나 결과는 항상 Observation으로 보존한다.
- **능동**: 포트 스캔, 디렉터리/vhost 브루트포스, 취약점 프로브, 인증 시도 등 타깃 상태를 바꾸거나 부하를 주는 행위. **`GO <recon_id>` 승인 뒤에만 실행한다.**

`진행해`, `알아서 해`, 과제를 맡겼다는 사실은 능동 정찰 승인이 아니다.

## Provenance — 발견의 출처 등급 (환각 통제의 핵심)

모든 발견은 아래 4등급 중 하나를 가진다. AI 추론은 **절대 `confirmed`로 자가 승격할 수 없다.**

| provenance | 의미 | 승격 조건 |
|---|---|---|
| `confirmed` | 원본 자산에 근거가 바이트 그대로 존재하거나, 결정론적 도구가 해시로 매칭 | `evidence_path` + `evidence_quote`(실제 파일에 존재) + `asset_sha256`(재계산 일치) |
| `inferred` | AI가 코드 패턴으로 추론한 하한/범위 | 근거 자산은 인용하되 단정하지 않음 (예: `createRoot` 존재 → React ≥18) |
| `guess` | 정황상 추측 (쿠키 이름 등 약한 단서) | 보고서에 추측으로만 표기 |
| `unknown` | 판단 불가 | **1급 출력이다. 판단 불가가 정답이면 이걸 뱉는 게 성공이다.** |

- 근거 자산이 없는 버전/제품 단정은 스키마상 불가능하다(Gate가 REVISE).
- "뭐라도 답해야 한다"는 압박을 두지 않는다. 모르면 `unknown`.

## CVE는 기억이 아니라 조회로

이 하네스는 제품·버전 특정까지만 한다. LLM의 학습된 CVE 지식은 신뢰하지 않는다.
CVE 번호·영향 버전·익스 존재 여부를 **기억에서 서술하지 않는다.** 그것은 CVE 매핑 하네스가 외부 소스(NVD/GHSA/OSV) 조회로 처리한다.

## 사람에게 남는 결정

- AI는 Scope를 승인하지 않는다.
- AI는 능동 정찰 실행을 승인하지 않는다.
- AI는 발견을 `confirmed`로 자가 확정하지 않는다(재검증 게이트 또는 결정론적 도구가 근거일 때만).
- AI는 최종 보고서 결론을 확정하지 않는다.

## Evidence

- AI Draft(추론)와 Tool Observation(수집 원본)을 분리한다.
- FACT / INFERENCE / UNKNOWN을 구분한다. FACT는 근거 자산 Ref를 인용한다.
- 요청, 응답 헤더, 원본 자산(JS/CSS/쿠키), 정규화 산출물, 도구 stdout/stderr/exit code를 보존한다.
- 실패·미매칭·UNKNOWN을 삭제하지 않는다.
- 원본 자산은 `captures/raw/`에 두고 `asset_sha256`으로 무결성을 고정한다. 이 값은 실제 파일에서 재계산 가능해야 한다(형식만 맞는 해시 = fabricated → Gate REVISE).

## 스크립트 자가개선 (self-repair)

CTF 당일 환경은 미지수라 수집기·도구 래퍼가 특정 타깃/도구 버전에서 깨질 수 있다. 실행 중 스크립트가
문제를 내면 다음 규율로 **원본을 보존한 채 사본을 자가개선**한다. 상세 절차는
[harness/policies/self-repair.md](harness/policies/self-repair.md).

- **허용 대상**: 수집기(collect_web/collect_spa)·정규화·도구 래퍼(active_recon/discover_vhost/
  discover_dns/extract_assets/aws_recon)·시그니처 데이터.
- **🔒 절대 금지(신뢰 앵커)**: 게이트(`scripts/check-recon.mjs`, `scripts/lib/checks.mjs`), `AGENTS.md`,
  `harness/policies/invariants.md`, provenance/증거 규율. **이들이 문제로 보이면 자가수정하지 말고 STOP,
  사람에게 보고**한다. 대상이 검증기를 고치면 통제 자체가 무너진다.
- **원본 불변**: 원본을 덮어쓰지 않고 사본을 만들어 고친다. 어느 변형본이 산출했는지 산출물에 기록한다.
- **검증 필수**: 자가개선 후 `npm test`(회귀)와 해당 타깃 게이트를 통과해야 채택한다. 실패하면 폐기(원본 유지).
- **기록**: 증상·원인·변경·검증 결과를 `targets/<host>/self-repair-log.md`에 남긴다. 실패 시도도 보존한다.

## Safety / STOP

- `scope.md`의 허용 대역(CTF가 지정한 서브넷/타깃) 밖의 IP·도메인 접근은 STOP.
- 공인 인터넷 타깃(CTF 랩 외부)·제3자 서비스로의 정찰은 STOP.
- Credential 수집·저장, 파괴, 지속성, Reverse Shell은 이 하네스 범위 밖이며 STOP.
- 인가 없는 광역 스캔(랩 대역 밖 무제한 스캔)은 STOP.
