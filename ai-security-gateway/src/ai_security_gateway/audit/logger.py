"""Append-only structured audit logging.

Every request/response passing through the gateway is recorded as a
JSON line, including a hash chain so tampering with historical log
entries is detectable (a lightweight analogue of a Merkle/blockchain
log, sufficient for a portfolio-grade demonstration of the concept).
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class AuditEvent:
    timestamp: float
    request_id: str
    client_id: str
    stage: str  # "input" | "output"
    decision: str
    reasons: list[str]
    injection_score: float
    dlp_summary: dict
    prev_hash: str = ""
    event_hash: str = field(default="", init=False)

    def compute_hash(self) -> str:
        payload = {k: v for k, v in asdict(self).items() if k != "event_hash"}
        blob = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()


class AuditLogger:
    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.log_path.exists():
            return "GENESIS"
        last_hash = "GENESIS"
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    last_hash = record.get("event_hash", last_hash)
                except json.JSONDecodeError:
                    continue
        return last_hash

    def log(
        self,
        request_id: str,
        client_id: str,
        stage: str,
        decision: str,
        reasons: list[str],
        injection_score: float,
        dlp_summary: dict,
    ) -> AuditEvent:
        event = AuditEvent(
            timestamp=time.time(),
            request_id=request_id,
            client_id=client_id,
            stage=stage,
            decision=decision,
            reasons=reasons,
            injection_score=injection_score,
            dlp_summary=dlp_summary,
            prev_hash=self._last_hash,
        )
        event.event_hash = event.compute_hash()
        self._last_hash = event.event_hash

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(event), sort_keys=True) + "\n")

        return event

    def verify_chain(self) -> bool:
        """Replays the log and confirms the hash chain is unbroken.
        Returns False the moment any entry's stored hash doesn't match
        what we recompute -- signalling tampering or corruption."""
        if not self.log_path.exists():
            return True

        prev_hash = "GENESIS"
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                stored_hash = record.pop("event_hash")
                if record.get("prev_hash") != prev_hash:
                    return False
                recomputed = hashlib.sha256(
                    json.dumps(record, sort_keys=True).encode("utf-8")
                ).hexdigest()
                if recomputed != stored_hash:
                    return False
                prev_hash = stored_hash
        return True
