import logging
from collections import Counter
from dataclasses import dataclass
from typing import List

from hnydaqd.audit.events import AuditEventType
from hnydaqd.audit.sink import AuditSink

logger = logging.getLogger(__name__)


@dataclass
class CorrelationAlert:
    rule: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    message: str


def detect_brute_force(sink: AuditSink, threshold: int = 3) -> List[CorrelationAlert]:
    """Deteksi banyak ACCESS_DENIED dalam waktu singkat per actor."""
    counts: Counter = Counter()
    for record in sink.get_records():
        if record["event_type"] == AuditEventType.ACCESS_DENIED.value:
            counts[record["actor_id"]] += 1

    alerts: List[CorrelationAlert] = []
    for actor, count in counts.items():
        if count >= threshold:
            alerts.append(
                CorrelationAlert(
                    rule="BRUTE_FORCE_ATTEMPT",
                    severity="HIGH",
                    message=f"Actor {actor} memiliki {count} akses ditolak. "
                    f"Kemungkinan percobaan enumerasi.",
                )
            )
    return alerts


def detect_repeated_dlp(sink: AuditSink, threshold: int = 5) -> List[CorrelationAlert]:
    """Deteksi user yang memicu banyak DLP redaksi (indikasi mencoba bypass)."""
    counts: Counter = Counter()
    for record in sink.get_records():
        if record["event_type"] == AuditEventType.DLP_REDACTION.value:
            counts[record["actor_id"]] += 1

    alerts: List[CorrelationAlert] = []
    for actor, count in counts.items():
        if count >= threshold:
            alerts.append(
                CorrelationAlert(
                    rule="REPEATED_DLP_TRIGGER",
                    severity="MEDIUM",
                    message=f"Actor {actor} memicu {count} DLP redaksi. "
                    f"Kemungkinan upaya mengeluarkan data sensitif.",
                )
            )
    return alerts


def detect_all(sink: AuditSink) -> List[CorrelationAlert]:
    """Jalankan semua rule korelasi."""
    alerts = []
    alerts.extend(detect_brute_force(sink))
    alerts.extend(detect_repeated_dlp(sink))

    for alert in alerts:
        logger.warning(
            "CORRELATION [%s/%s] %s",
            alert.rule,
            alert.severity,
            alert.message,
        )
    return alerts
