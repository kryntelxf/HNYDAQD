import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from hnydaqd.audit.events import AuditEventType

logger = logging.getLogger(__name__)


class AuditIntegrityError(Exception):
    """Dilempar ketika rantai audit rusak (tamper terdeteksi)."""
    pass


@dataclass
class AuditRecord:
    event_type: AuditEventType
    actor_id: str
    details: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    previous_hash: str = ""
    record_hash: str = ""

    def compute_hash(self) -> str:
        """Menghitung hash dari isi record + hash record sebelumnya."""
        payload = {
            "event_type": self.event_type.value,
            "actor_id": self.actor_id,
            "details": self.details,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
        }
        serialized = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class AuditSink:
    """
    Audit sink in-memory dengan hash chain tamper-evident.
    Di produksi, ini akan ditulis ke append-only storage (S3 Object Lock,
    database immutable, atau syslog WORM).
    """

    def __init__(self) -> None:
        self._records: List[AuditRecord] = []
        self._last_hash: str = "0" * 64  # genesis hash

    def record(
        self,
        event_type: AuditEventType,
        actor_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        record = AuditRecord(
            event_type=event_type,
            actor_id=actor_id,
            details=details or {},
            previous_hash=self._last_hash,
        )
        record.record_hash = record.compute_hash()
        self._records.append(record)
        self._last_hash = record.record_hash

        logger.debug(
            "Audit: %s oleh %s (hash=%s)",
            event_type.value,
            actor_id,
            record.record_hash[:12],
        )
        return record

    def verify_integrity(self) -> bool:
        """
        Memverifikasi seluruh rantai hash. Melempar AuditIntegrityError
        jika ada record yang diubah.
        """
        expected_previous = "0" * 64

        for i, record in enumerate(self._records):
            if record.previous_hash != expected_previous:
                raise AuditIntegrityError(
                    f"Record #{i} memiliki previous_hash yang salah."
                )
            recomputed = record.compute_hash()
            if recomputed != record.record_hash:
                raise AuditIntegrityError(
                    f"Record #{i} telah diubah (hash tidak cocok)."
                )
            expected_previous = record.record_hash

        return True

    def get_records(self) -> List[Dict[str, Any]]:
        return [asdict(r) for r in self._records]

    def count(self) -> int:
        return len(self._records)


# Instance global default untuk dipakai aplikasi
default_audit_sink = AuditSink()
