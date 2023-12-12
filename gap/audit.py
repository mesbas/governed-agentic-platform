"""Tamper-evident, append-only audit log.

Each entry stores the hash of the previous entry, so editing or deleting any
past entry breaks the chain and `verify()` returns False.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(body: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self.entries: list[dict[str, Any]] = []
        self.path = Path(path) if path else None

    def append(self, event: str, payload: dict[str, Any]) -> dict[str, Any]:
        # Round-trip through JSON so later mutation of the caller's dict
        # cannot change what was recorded.
        safe_payload = json.loads(json.dumps(payload, default=str))
        body = {
            "seq": len(self.entries),
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "payload": safe_payload,
            "prev_hash": self.entries[-1]["hash"] if self.entries else GENESIS,
        }
        entry = {**body, "hash": _digest(body)}
        self.entries.append(entry)
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def verify(self) -> bool:
        prev = GENESIS
        for i, entry in enumerate(self.entries):
            body = {k: v for k, v in entry.items() if k != "hash"}
            if entry.get("seq") != i or entry.get("prev_hash") != prev:
                return False
            if _digest(body) != entry.get("hash"):
                return False
            prev = entry["hash"]
        return True

    def events_for(self, request_id: str) -> list[dict[str, Any]]:
        return [e for e in self.entries if e["payload"].get("request_id") == request_id]

    @classmethod
    def load(cls, path: str | Path) -> "AuditLog":
        log = cls()
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                log.entries.append(json.loads(line))
        log.path = Path(path)
        return log
