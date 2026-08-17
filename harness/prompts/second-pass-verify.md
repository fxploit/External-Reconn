# 작업 계약: 2차 재검증 (Second-Pass Verify)

> `confirmed`로 승격되거나 다음 하네스로 넘어갈 고가치 발견을 **맥락 제거 상태**로 재판정한다.
> 단일 판정은 확증편향에 취약하므로, 원본 증거만 주고 "이 근거가 이 제품·버전을 지지하는가"를
> 다시 묻는다. 판정이 어긋나면 스크립트가 등급을 자동 강등한다.

## 입력 (무엇만 주는가)

각 재판정 항목에는 **판정에 필요한 최소 증거만** 담는다. 제품명·버전·다른 발견·추론 문구는
**주지 않는다**(맥락 제거 — 되묻기 때문에 확증편향을 막는다).

```json
{
  "second_pass_input": [
    {
      "finding_id": "FND-003",
      "evidence_quote": "EXACT_BYTES_COPIED_FROM_ASSET",
      "asset_kind": "js",
      "evidence_excerpt": "evidence_path 파일에서 인용 주변의 원문 일부(또는 파일 앞부분)"
    }
  ]
}
```

- `evidence_quote`는 1차 판정이 근거로 제시한 실제 파일 부분 문자열이다.
- `evidence_excerpt`는 그 파일의 원문 일부다(인용이 어느 코드/문맥에서 나왔는지).
- 이 두 가지가 **재판정의 유일한 근거**다.

## 질문

**"이 증거(인용 + 원문 일부)는 어떤 제품·프레임워크·버전을 지지하는가?"** 를 묻는 것이 아니다.
실제 질문은: **"이 증거는 그 제품·버전을 지지하는가?"** — 그러나 제품·버전은 알려주지 않으므로,
당신은 증거가 **구체적으로 무엇을 지지하는지**(제품 계열, 가능한 버전 범위)를 판정한다.

## 출력 스키마

```json
{
  "verdicts": [
    {
      "finding_id": "FND-003",
      "verdict": "support",
      "product_supported": "React",
      "version_supported": ">=18",
      "reason": "createRoot(concurrent root) API 호출부가 파일에 바이트 그대로 존재"
    }
  ]
}
```

- `verdict`는 셋 중 하나:
  - `support` — 증거가 1차 판정의 제품·버전을 **명확히 지지**한다.
  - `contradict` — 증거가 그 제품·버전과 **모순/불일치**다(오탐 가능성).
  - `unknown` — 근거로는 지지·반박 판단 불가.
- `product_supported`/`version_supported`는 증거가 실제로 지지하는 값(자신의 판단).
- `reason`은 **인용·원문에 근거한** 짧은 설명. 지어낸 인용은 금지(바로 옆 원문과 대조 가능).

## 규칙

1. **맥락은 입력에 있는 것뿐이다.** 1차 판정의 product/version/provenance를 모른다고 가정하고 판단한다.
2. **근거는 자산에 있다.** LLM의 사전 지식은 보조일 뿐, 판정 근거는 `evidence_excerpt`에 있어야 한다.
3. **모르면 `unknown`.** 지지·반박을 억지로 고르지 않는다.
4. **`contradict`는 명확할 때만.** "흔치 않다", "확실하지 않다"는 `unknown`이다.
5. 출력은 위 스키마의 JSON 하나. 마크다운/표/코드블록 금지.

## 적용 (스크립트)

`scripts/second_pass.py <host> --apply verdicts.json`:
- `support` → `verified_by`에 `second-pass:support` 추가. provenance 유지.
- `contradict` → `verified_by`에 `second-pass:contradict` 추가. **1차 판정과 갈리므로 강등**
  (`confirmed` → `inferred`, `inferred`/`guess`는 그대로 유지).
- `unknown` → `verified_by`에 `second-pass:unknown` 추가. 등급 불변(보수적).
- 강등/부여 내역은 stdout으로 보고하고, 게이트(`npm run check`)로 최종 확인한다.
