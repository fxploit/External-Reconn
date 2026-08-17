# 작업 계약: AI Fallback 추론 (unmatched 자산)

> 이 계약은 **정찰 하네스의 유일한 AI 허용 지점**이다. 결정론적 시그니처가 못 잡은
> `unmatched` 자산을 코드 패턴으로 추론한다. AI는 환각 진원지이므로 아래 규칙은 전부
> 하드 제약이다. 어기면 병합 스크립트 또는 게이트가 REVISE로 되돌린다.

## 입력

`targets/<host>/findings.json` 의 `unmatched[]` 배열. 각 항목은 정규화본/원본 텍스트를
가지며, 그 텍스트가 곧 분석 대상이다. 항목을 읽기 전에 `evidence_path` 로 지정된 파일을
열어 **실제 바이트**를 분석한다.

## 출력 스키마 (JSON 배열)

```json
[
  {
    "asset_id": "AST-004",
    "product": "ExampleFramework",
    "version": "2.1.0",
    "version_bound": "UNSET",
    "provenance": "inferred",
    "evidence_quote": "EXACT_BYTES_COPIED_FROM_ASSET",
    "reasoning": "이 자산에서 이 근거를 뽑은 이유 (바이트 기준)"
  }
]
```

## 하드 규칙 (위반 = REVISE)

1. **`provenance`는 `inferred` / `guess` / `unknown` 셋 중 하나만.** `confirmed`는 **금지**다.
   - `inferred` — 코드 패턴(API·심볼·에러 문자열·파일명 관용구)으로 도출한 하한/범위/버전.
   - `guess` — 약한 정황(쿠키 이름, 흔한 관용구 등)만 있을 때.
   - `unknown` — 판단 불가. **이게 정답이고 성공이다.** 억지로 맞출 필요가 없다.
2. **제품·버전은 자산에서 바이트 그대로 인용 가능할 때만 제시한다.**
   `evidence_quote`는 자산 파일에서 **복사한 실제 부분 문자열**이어야 한다.
   패턴을 바꿔 쓰거나, 부분 문자열이 아닌 조합, 공백 정규화는 금지.
   인용할 수 없으면 `provenance: unknown`을 반환한다.
3. **인용 없는 추측 금지.** `evidence_quote`가 없거나 자산에 없는 인용은 fabricated다.
4. **`reasoning`은 그 인용이 왜 그 제품·버전을 지지하는지**를 인용에 기반해 서술한다.
   LLM의 사전 지식(CVE, 공식문서)은 근거가 아니다. 자산에 있는 것만 근거다.
5. **모르면 모른다.** 판단 불가는 `unknown`으로 반환. "가능성 있는 것"을 나열하지 않는다.
6. **출력은 위 스키마의 JSON 배열 하나만.** 마크다운 설명, 표, 코드블록 안 JSON은 병합 실패한다.

## 판정 가이드 (순서)

1. 자산을 열고 제품을 암시하는 **고유 심볼/문자열**을 찾는다(번들 내부 버전 대입, 네임스페이스,
   에러 문자열, 파일명 관용구, 특정 API 시그니처).
2. 정확 버전 문자열이 바이트로 존재하면 `inferred`(버전 명시). 버전을 특정하지 못하면
   버전 하한/범위 추론(`version_bound`, 예: `>=18`) 또는 `version: unknown`.
3. 근거가 유일하지만 약하면 `guess`. 판단 불가면 `unknown`.

## 예시

- 자산에 `window.__PKG = {"name":"acme-ui","version":"4.7.1"}` 가 있으면:
  `product: acme-ui, version: 4.7.1, provenance: inferred, evidence_quote: "\"name\":\"acme-ui\",\"version\":\"4.7.1\""`
- 자산에 `this.xhr.send(JSON.stringify({v:"1.0"}))` 만 있고 제품 단서가 없으면: `provenance: unknown`.

## 검증 (이 계약을 지켰는지)

- 병합 스크립트(`scripts/merge_fallback.py`)는 `evidence_quote`의 UTF-8 바이트가
  `evidence_path` 파일에 실제로 있는지 **병합 전에** 확인한다. 없으면 해당 판정을 거부하고
  로그로 남긴다(스코프 밖 삭제 금지).
- 병합 후 반드시 게이트 재실행: `npm run check -- <host>`. 지어낸 인용은
  "evidence_quote not found … fabricated"로 REVISE 된다(안전망).
