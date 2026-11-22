import pytest

from hnydaqd.audit.events import AuditEventType
from hnydaqd.audit.sink import AuditIntegrityError, AuditSink


def test_empty_sink_is_valid() -> None:
    sink = AuditSink()
    assert sink.verify_integrity() is True
    assert sink.count() == 0


def test_record_increases_count() -> None:
    sink = AuditSink()
    sink.record(AuditEventType.AUTH_SUCCESS, "user_1", {"ip": "1.2.3.4"})
    sink.record(AuditEventType.ACCESS_DENIED, "user_2", {"reason": "role"})
    assert sink.count() == 2


def test_chain_is_valid_after_records() -> None:
    sink = AuditSink()
    sink.record(AuditEventType.AUTH_SUCCESS, "user_1")
    sink.record(AuditEventType.CONTEXT_BLOCKED, "user_1", {"chunk": "abc"})
    sink.record(AuditEventType.DLP_REDACTION, "user_2", {"pattern": "sk-"})
    assert sink.verify_integrity() is True


def test_hash_chain_links_correctly() -> None:
    sink = AuditSink()
    r1 = sink.record(AuditEventType.AUTH_SUCCESS, "u1")
    r2 = sink.record(AuditEventType.AUTH_SUCCESS, "u1")
    assert r1.previous_hash == "0" * 64
    assert r2.previous_hash == r1.record_hash


def test_tampered_record_is_detected() -> None:
    sink = AuditSink()
    sink.record(AuditEventType.AUTH_SUCCESS, "u1")
    r2 = sink.record(AuditEventType.ACCESS_DENIED, "u2")
    # Simulasi serangan: attacker mengubah detail record yang sudah tercatat.
    r2.details = {"reason": "dihapus oleh attacker"}
    with pytest.raises(AuditIntegrityError):
        sink.verify_integrity()


def test_tampered_previous_hash_is_detected() -> None:
    sink = AuditSink()
    sink.record(AuditEventType.AUTH_SUCCESS, "u1")
    r2 = sink.record(AuditEventType.AUTH_SUCCESS, "u2")
    r2.previous_hash = "f" * 64  # attacker memutus rantai
    with pytest.raises(AuditIntegrityError):
        sink.verify_integrity()


def test_get_records_returns_dict() -> None:
    sink = AuditSink()
    sink.record(AuditEventType.PROVIDER_ROUTED, "u1", {"provider": "PRIVATE"})
    records = sink.get_records()
    assert len(records) == 1
    assert records[0]["event_type"] == "PROVIDER_ROUTED"
    assert records[0]["actor_id"] == "u1"
