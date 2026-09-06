import json

from ai_security_gateway.audit.logger import AuditLogger


def test_log_creates_valid_jsonl(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(log_path))
    logger.log(
        request_id="req-1",
        client_id="client-a",
        stage="input",
        decision="allow",
        reasons=["No policy violations detected."],
        injection_score=0.0,
        dlp_summary={},
    )
    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["request_id"] == "req-1"
    assert record["prev_hash"] == "GENESIS"


def test_hash_chain_links_entries(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(log_path))
    e1 = logger.log("req-1", "client-a", "input", "allow", ["ok"], 0.0, {})
    e2 = logger.log("req-2", "client-a", "output", "allow", ["ok"], 0.0, {})
    assert e2.prev_hash == e1.event_hash


def test_verify_chain_detects_tampering(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(log_path))
    logger.log("req-1", "client-a", "input", "allow", ["ok"], 0.0, {})
    logger.log("req-2", "client-a", "output", "allow", ["ok"], 0.0, {})
    assert logger.verify_chain() is True

    # Tamper with the log file directly.
    lines = log_path.read_text().strip().splitlines()
    tampered = json.loads(lines[0])
    tampered["decision"] = "block"  # flip a field after the fact
    lines[0] = json.dumps(tampered)
    log_path.write_text("\n".join(lines) + "\n")

    tampered_logger = AuditLogger(str(log_path))
    assert tampered_logger.verify_chain() is False
