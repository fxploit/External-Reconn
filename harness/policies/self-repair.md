# 스크립트 자가개선 (self-repair) 정책

CTF 당일 환경은 미지수다. 수집기가 특정 사이트에서, 도구 래퍼가 특정 도구 버전에서 깨질 수 있다.
이 정책은 실행 중 스크립트가 문제를 낼 때 에이전트가 **통제(게이트·증거 규율)를 훼손하지 않고
재현 가능하게** 스스로 고치는 절차를 규정한다.

이 문서는 런타임 계약이다([AGENTS.md](../../AGENTS.md) "스크립트 자가개선"이 이를 참조).
빌드(구현) 지시는 TASK.md T20.

## 1. 신뢰 앵커 — 절대 자가수정 금지

다음은 하네스의 신뢰 근거다. 대상이 이걸 고치면 통제가 무너진다. **문제로 보여도 자가수정하지 말고
STOP → 사람에게 보고**한다.

- `scripts/check-recon.mjs`, `scripts/lib/checks.mjs` (게이트/검증기)
- `AGENTS.md`, `harness/policies/invariants.md` (계약·불변조건)
- provenance 등급·증거 바인딩 규율 자체

## 2. 자가개선 허용 대상

환경에 따라 깨지는 **데이터 수집 계층**만:

- 수집기: `collect_web.py`, `collect_spa.py`
- 정규화: `normalize_js.py`
- 도구 래퍼: `active_recon.py`, `discover_vhost.py`, `discover_dns.py`, `extract_assets.py`, `aws_recon.py`
- 시그니처 데이터: `harness/signatures/**`

## 3. 절차

1. **문제 포착**: 스크립트가 실패/오작동하면 증상(에러·비정상 출력)을 Observation으로 보존한다.
2. **원본 불변, 사본 작업**: 원본을 덮어쓰지 않는다. 사본을 만든다:
   `scripts/variants/<원본파일명>.<target>.<YYYYMMDD-HHMMSS>.py`
3. **최소 수정**: 원인에 국한한 최소 변경. 전면 재작성 금지.
4. **산출물 출처 표기**: 그 실행이 어느 변형본이었는지 산출물에 남긴다
   (manifest/finding의 `produced_by` 필드 = 사본 경로).
5. **검증(채택 조건)**: 자가개선본으로 산출한 뒤
   - `npm test` (회귀) 통과, **그리고**
   - 해당 타깃 게이트 `npm run check -- <target>` 가 의도한 결과(GO 등)
   둘 다 통과해야 **채택**. 하나라도 실패하면 변형본을 **폐기**(원본 유지)하고 로그에 기록한다.
6. **기록**: 아래 로그를 남긴다. 실패한 시도도 삭제하지 않는다.
7. **보고**: 자가개선이 일어나면 결과 보고(오케스트레이터/사람)에 명시한다. 원본 반영 여부는 사람이 정한다.

## 4. 로그 형식

`targets/<host>/self-repair-log.md` (+ 기계가독 `self-repair-log.json`). 항목마다:

```
## <ts> <원본파일명>
- 사본: scripts/variants/<...>.py
- 증상: <에러/비정상> (Observation ref: captures/observation/<...>)
- 원인 가설: <...>
- 변경 요약: <무엇을 왜> (diff ref: <...>)
- 검증: npm test = pass/fail, gate(<target>) = GO/REVISE/STOP
- 판정: 채택 / 폐기(사유)
```

## 5. 왜 이렇게 (환각 통제와의 관계)

자가개선은 유연성을 주지만, 대상이 검증기를 손대면 환각 통제가 무력화된다. 그래서:
**고칠 수 있는 것(수집·도구)과 절대 못 고치는 것(검증기·계약)을 분리**하고, 개선본의 산출물도
**같은 게이트로 재검증**하며, 모든 변경을 근거와 함께 로그로 남겨 **재현·감사 가능**하게 한다.
자가개선의 자유도만큼 검증기를 잠가서 상쇄하는 구조다.
