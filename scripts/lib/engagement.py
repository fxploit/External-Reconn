#!/usr/bin/env python3
"""T31 교전 감사 추적 공용 헬퍼.

새 주장을 만들지 않고, 실행·발견의 기존 ref와 시각만 append-only JSONL에 기록한다.
"""
import json
import os
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def append_event(target, event):
    path = os.path.join(ROOT, "targets", target, "engagement-log.jsonl")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    record = dict(event)
    record.setdefault("timestamp", now_iso())
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    return path


def go_approval(target, recon_id, command, scope=None):
    return append_event(target, {
        "event": "go-approval",
        "recon_id": recon_id,
        "command": command,
        "scope": scope,
        "approved_at": now_iso(),
    })


def stamp_findings(findings, produced_by):
    """기존 시각은 보존하고 새 finding에만 discovered_at/produced_by를 채운다."""
    ts = now_iso()
    for finding in findings:
        finding.setdefault("discovered_at", ts)
        finding.setdefault("produced_by", produced_by)
    return findings
