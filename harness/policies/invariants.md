# 고정 불변조건 (Recon)

- Target은 `scope.md` 허용 대역 안에 있어야 한다. 밖이면 STOP.
- 능동 정찰은 `GO <recon_id>` 뒤 실행한다. 수동 수집은 상태를 바꾸지 않으므로 예외지만 Observation으로 보존한다.
- AI Draft(추론)와 Tool Observation(수집 원본)을 분리한다.
- 요청, 응답 헤더, 원본 자산, 정규화 산출물, stdout/stderr/exit code를 보존한다.
- `provenance: confirmed`는 검증된 근거 자산 Ref가 있어야 한다.
- 실패·미매칭·UNKNOWN을 삭제하지 않는다.

## 역할

- **AI**: 초안·추론을 제안한다. Scope, 능동 실행, `confirmed` 승격, 최종 결론을 스스로 승인하지 않는다.
- **Tool**: 수집·정규화·매칭 원본을 Observation으로 기록하며 해석을 더하지 않는다.
- **사람**: Scope, `GO <recon_id>`, `confirmed`/`report_eligible` 판정, 최종 결론을 확정한다.

## Provenance 규율

- `confirmed`: 원본 자산에 근거 문자열이 바이트 그대로 존재(`evidence_quote`가 `evidence_path` 파일의 실제 부분 문자열),
  또는 결정론적 도구의 해시 매칭. `asset_sha256`은 실제 파일에서 재계산해 일치해야 한다.
- `inferred`: AI가 코드 패턴으로 도출한 하한/범위. 근거 자산을 인용하되 단정하지 않는다.
- `guess`: 약한 정황 단서. 보고서에 추측으로만 표기.
- `unknown`: 판단 불가. 정식 값이며 삭제·강제 확정 대상이 아니다.
- **AI 추론은 `confirmed`로 자가 승격할 수 없다.** 결정론적 도구 매칭 또는 재검증 게이트를 통과할 때만 `confirmed`.

## 증거 바인딩 (환각 통제)

- **버전/제품 단정에는 근거 자산이 필수다.** `evidence_path`가 실재하지 않으면 Gate가 REVISE.
- **`evidence_quote`는 `evidence_path` 파일의 실제 부분 문자열이어야 한다.** 파일에 없는 인용 = fabricated → REVISE.
  (checks의 matcher 평가와 같은 원리: 선언한 근거가 실제 원본과 일치하는지 재검증한다.)
- **`asset_sha256`은 실제 파일 내용의 sha256과 일치해야 한다.** 형식만 맞는 hex 문자열(형식 유효, 근거 없음) = fabricated → REVISE.
- **사람에게 하는 서술은 원본 파일에서 값을 복사한다.** Target·포트·버전·해시를 기억이나 참고자료에서 재입력하지 않는다.
  원본(`captures/manifest.json`, `findings.json`)과 다르면 Gate가 REVISE로 잡는다.

## 재사용 패턴

- **시그니처는 데이터로 분리한다.** 제품·버전 규칙은 `harness/signatures/*.json`에 둔다. 스크립트 로직이 아니라 데이터를 늘린다.
- **결정론적 우선, AI는 fallback.** 수집·정규화·매칭은 스크립트로 결정론적이게. AI는 미매칭 자산 추론과 관련성 판단에만 개입.
- **미스는 지운다가 아니라 남긴다.** 매칭 실패 자산은 `unmatched`로 보존해 다음 세션·다음 하네스가 이어받는다.
- **결과 클래스를 분리한다.** 접속 실패(연결 거부/timeout)와 정상 차단(403/404)을 같은 결과로 취급하지 않는다.

## 신뢰 앵커 불변 (자가개선 가드레일)

- 스크립트가 현장에서 깨지면 **원본을 보존한 채 사본을 자가개선**할 수 있다(수집기·정규화·도구
  래퍼·시그니처 한정). 절차·로그는 [self-repair.md](self-repair.md), 작업 지시는 TASK.md T20.
- **검증기와 계약은 자가수정 절대 금지(신뢰 앵커)**: `scripts/check-recon.mjs`, `scripts/lib/checks.mjs`,
  `AGENTS.md`, 이 `invariants.md`, provenance/증거 규율. 이들이 문제로 보이면 **자가수정하지 말고 STOP,
  사람에게 보고**한다. 대상이 검증기를 고치면 통제 자체가 무너진다.
- 자가개선본의 산출물도 **동일 게이트로 재검증**하고, 모든 변경을 근거와 함께 로그로 남긴다.

## STOP 조건

- `진행해`, `알아서 해`, 과제를 맡겼다는 사실은 능동 정찰 승인이 아니다.
- 정확한 `GO <recon_id>`가 아니면 능동 정찰을 실행하지 않는다.
- `scope.md` 허용 대역 밖 Target은 STOP.
- Credential 수집·저장, 파괴, 지속성, Reverse Shell, 대역 밖 무제한 Scan은 STOP.
- 근거 자산 없는 (product/version) 단정을 `confirmed`로 반영하려 하면 REVISE.
