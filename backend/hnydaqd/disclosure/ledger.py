import logging
from typing import Any, Dict, List

from hnydaqd.config import ClassificationLevel

logger = logging.getLogger(__name__)


class DisclosureRiskError(Exception):
    """Dilempar ketika user terdeteksi mencoba melakukan cumulative disclosure."""


class DisclosureLedger:
    def __init__(self) -> None:
        self._history: Dict[str, List[ClassificationLevel]] = {}
        self.MAX_SENSITIVE_ACCESSES = 3

    def record_and_verify(
        self, user_id: str, requested_chunks: List[Dict[str, Any]]
    ) -> None:
        if user_id not in self._history:
            self._history[user_id] = []

        for chunk in requested_chunks:
            level = chunk.get("classification", ClassificationLevel.PUBLIC)
            if level in [
                ClassificationLevel.HIGHLY_CONFIDENTIAL,
                ClassificationLevel.RAW_SECRET,
            ]:
                self._history[user_id].append(level)

        self._history[user_id] = self._history[user_id][-10:]

        total_sensitive_recent = sum(
            1
            for level in self._history[user_id]
            if level
            in [
                ClassificationLevel.HIGHLY_CONFIDENTIAL,
                ClassificationLevel.RAW_SECRET,
            ]
        )

        if total_sensitive_recent > self.MAX_SENSITIVE_ACCESSES:
            logger.warning(
                "SECURITY ALERT: User %s terdeteksi melakukan "
                "Cumulative Disclosure Attack!",
                user_id,
            )
            raise DisclosureRiskError(
                "Akses diblokir: Anda telah mengakses terlalu banyak "
                "informasi sensitif dalam waktu singkat. Pola ini "
                "terdeteksi sebagai upaya ekstraksi data rahasia."
            )


disclosure_ledger = DisclosureLedger()
