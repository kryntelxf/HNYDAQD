from hnydaqd.audit.correlation import (
    detect_all,
    detect_brute_force,
    detect_repeated_dlp,
)
from hnydaqd.audit.events import AuditEventType
from hnydaqd.audit.sink import AuditSink


def test_no_alert_on_clean_audit() -> None:
    sink = AuditSink()
    sink.record(AuditEventType.AUTH_SUCCESS, "u1")
    sink.record(AuditEventType.AUTH_SUCCESS, "u2")
    alerts = detect_all(sink)
    assert len(alerts) == 0


def test_brute_force_detected_at_threshold() -> None:
    sink = AuditSink()
    for _ in range(3):
        sink.record(AuditEventType.ACCESS_DENIED, "attacker")
    alerts = detect_brute_force(sink)
    assert len(alerts) == 1
    assert alerts[0].rule == "BRUTE_FORCE_ATTEMPT"
    assert alerts[0].severity == "HIGH"


def test_brute_force_not_triggered_below_threshold() -> None:
    sink = AuditSink()
    for _ in range(2):
        sink.record(AuditEventType.ACCESS_DENIED, "attacker")
    alerts = detect_brute_force(sink)
    assert len(alerts) == 0


def test_repeated_dlp_detected() -> None:
    sink = AuditSink()
    for _ in range(5):
        sink.record(AuditEventType.DLP_REDACTION, "leaky_user")
    alerts = detect_repeated_dlp(sink)
    assert len(alerts) == 1
    assert alerts[0].rule == "REPEATED_DLP_TRIGGER"


def test_mixed_attacks_produce_multiple_alerts() -> None:
    sink = AuditSink()
    for _ in range(3):
        sink.record(AuditEventType.ACCESS_DENIED, "multi_attacker")
    for _ in range(5):
        sink.record(AuditEventType.DLP_REDACTION, "multi_attacker")
    alerts = detect_all(sink)
    assert len(alerts) == 2


def test_different_actors_are_not_merged() -> None:
    sink = AuditSink()
    for i in range(5):
        sink.record(AuditEventType.ACCESS_DENIED, f"actor_{i}")
    alerts = detect_brute_force(sink)
    # Setiap actor hanya muncul 1x, di bawah threshold 3
    assert len(alerts) == 0
