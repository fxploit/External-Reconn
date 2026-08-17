# Signature Database

제품·버전 핑거프린트 규칙을 **데이터**로 둔다. 새 제품 지원은 스크립트가 아니라 이 디렉터리에 JSON을 추가한다.
`scripts/fingerprint.py`가 모든 `*.json`을 읽어 수집 자산에 매칭한다.

## 스키마

```json
{
  "product": "React",
  "signatures": [
    {
      "id": "react-createRoot",
      "asset_kinds": ["js"],
      "match": { "type": "regex", "pattern": "createRoot\\s*\\(" },
      "implies": { "version_bound": ">=18", "provenance": "inferred" },
      "note": "createRoot API introduced in React 18"
    }
  ]
}
```

- `match.type`: `regex` 또는 `literal`.
- `match.pattern`: 정규식. 이름있는 그룹 `(?P<version>...)`가 있으면 정확 버전으로 캡처한다.
- `implies.version_bound`: 정확 버전을 못 잡을 때의 하한/범위 문자열(예: `>=18`, `15-16`).
- `implies.provenance`:
  - `confirmed` — 원본에 근거 문자열이 바이트 그대로 존재(정확 버전 캡처 등). 결정론적으로 참.
  - `inferred` — API/패턴 존재로 도출한 범위. 단정 아님.
  - `guess` — 약한 정황.
- 정확 버전을 캡처하면 fingerprint.py가 provenance를 `confirmed`로 승격한다(문자열이 파일에 실재하므로).
  범위만 도출하면 시그니처의 `implies.provenance`를 그대로 쓴다.

## 원칙

- 근거 없는 매칭은 만들지 않는다. `evidence_quote`가 실제 파일 부분 문자열이 되도록 pattern을 설계한다.
- 미매칭은 fingerprint.py가 `unmatched`로 보존한다. 시그니처를 무리하게 넓혀 오탐을 만들지 않는다.
