#!/usr/bin/env python3
"""검증된 정찰 산출물 조립기(T32).

findings/manifest/engagement-log/command-log을 읽어 report.md를 렌더링한다.
새 사실이나 해석을 생성하지 않는다. 각 finding은 evidence_path/evidence_quote를 그대로 인용한다.
"""
import argparse
import json
import os
import re
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


def load_jsonl(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    rows.append({"event": "invalid-jsonl", "raw": line.rstrip()})
    return rows


def md(value):
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def main():
    ap = argparse.ArgumentParser(description="Build deterministic recon report")
    ap.add_argument("target")
    args = ap.parse_args()
    base = os.path.join(ROOT, "targets", args.target)
    fpath = os.path.join(base, "findings.json")
    mpath = os.path.join(base, "captures", "manifest.json")
    if not os.path.exists(fpath):
        print(f"[!] findings.json missing: {fpath}")
        return 2
    doc = load_json(fpath, {})
    manifest = load_json(mpath, {})
    findings = doc.get("findings", [])
    engagement = load_jsonl(os.path.join(base, "engagement-log.jsonl"))
    commands = load_jsonl(os.path.join(base, "captures", "observation", "run-log", "command-log.jsonl"))
    counts = Counter(f.get("provenance", "unknown") for f in findings)
    assets = manifest.get("assets", [])
    approvals = [e for e in engagement if e.get("event") == "go-approval"]

    lines = [
        f"# Recon Report — {args.target}", "",
        "> 이 문서는 findings.json, manifest.json, engagement-log.jsonl, command-log.jsonl의 결정론적 렌더링이다."
        " AI가 새 사실을 생성하지 않는다.", "",
        "## 요약", "",
        f"- Target: `{args.target}`",
        f"- Entry URL: `{manifest.get('entry_url', 'UNSET')}`",
        f"- Assets: {len(assets)}",
        f"- Findings: {len(findings)} (confirmed={counts['confirmed']}, inferred={counts['inferred']}, "
        f"guess={counts['guess']}, unknown={counts['unknown']})",
        f"- Engagement events: {len(engagement)}",
        f"- Command records: {len(commands)}", "",
        "## 범위·승인", "",
        f"- Scope source: `scope.md` (gate가 검증한 target: `{args.target}`)",
        f"- GO approvals recorded: {len(approvals)}", "",
    ]
    for event in approvals:
        lines.append(f"- `{event.get('recon_id')}` at `{event.get('approved_at', event.get('timestamp'))}` "
                     f"scope=`{md(event.get('scope'))}`")

    lines += ["", "## 타임라인", "", "| 시각 | 이벤트 | ref | command |", "|---|---|---|---|"]
    for event in sorted(engagement, key=lambda x: x.get("timestamp", "")):
        ref = event.get("findings_ref") or event.get("manifest_ref") or event.get("command_log_ref") or ""
        lines.append(f"| {md(event.get('timestamp'))} | {md(event.get('event'))} | `{md(ref)}` | |")
    for event in sorted(commands, key=lambda x: x.get("timestamp_start", "")):
        command = " ".join(str(x) for x in event.get("command", []))
        lines.append(f"| {md(event.get('timestamp_start'))} | command exit={event.get('exit_code')} | "
                     f"`{md(event.get('stdout_ref'))}`, `{md(event.get('stderr_ref'))}` | `{md(command)}` |")

    for title, provenance in (("확정 발견", "confirmed"), ("추론 발견", "inferred"),
                              ("추측 발견", "guess"), ("미확정/Unknown", "unknown")):
        lines += ["", f"## {title}", "", "| ID | 제품 | 버전/범위 | provenance | 근거 |", "|---|---|---|---|---|"]
        selected = [f for f in findings if f.get("provenance") == provenance]
        if not selected:
            lines.append("| - | - | - | - | 없음 |")
        for f in selected:
            ref = f.get("evidence_path", "UNSET")
            quote = f.get("evidence_quote", "UNSET")
            lines.append(f"| {md(f.get('finding_id'))} | {md(f.get('product'))} | "
                         f"{md(f.get('version'))} {md(f.get('version_bound'))} | {provenance} | "
                         f"`{md(ref)}` — `{md(quote)}` |")

    lines += ["", "## 증거·재현 부록", "", "| 항목 | 값 |", "|---|---|"]
    lines.append(f"| runtime_image_digest | `{md(manifest.get('runtime_image_digest', 'UNSET'))}` |")
    lines.append(f"| produced_by | `{md(manifest.get('produced_by', 'UNSET'))}` |")
    for event in commands:
        lines.append(f"| command stdout sha256 | `{md(event.get('stdout_sha256'))}` |")
        lines.append(f"| command stderr sha256 | `{md(event.get('stderr_sha256'))}` |")
    lines += ["", "## 다음 하네스 입력", "", "- `confirmed` product/version만 CVE 매핑 하네스의 자동 입력으로 사용한다.",
              "- 모든 해석은 원본 evidence ref와 게이트 검증 결과를 함께 재검토해야 한다.", ""]

    out = os.path.join(base, "report.md")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))
    print(f"[*] report written: {os.path.relpath(out, ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
