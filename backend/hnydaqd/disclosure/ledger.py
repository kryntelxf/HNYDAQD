import logging
from typing import List, Dict, Any
from hnydaqd.config import ClassificationLevel

logger = logging.getLogger(__name__)

class DisclosureRiskError(Exception):
    """Dilempar ketika user terdeteksi mencoba melakukan cumulative disclosure."""
    pass

class DisclosureLedger:
    def __init__(self):
        # Menyimpan riwayat klasifikasi sensitif yang pernah diakses oleh user
        # Format: { "user_id": [ClassificationLevel.RAW_SECRET, ClassificationLevel.HIGHLY_CONFIDENTIAL] }
        self._history: Dict[str, List[ClassificationLevel]] = {}
        
        # Batas toleransi sebelum diblokir
        self.MAX_SENSITIVE_ACCESSES = 3

    def record_and_verify(self, user_id: str, requested_chunks: List[Dict[str, Any]]) -> None:
        """
        Mencatat akses dan memverifikasi apakah user sudah melewati batas aman.
        Jika melewati batas, raise DisclosureRiskError.
        """
        if user_id not in self._history:
            self._history[user_id] = []

        sensitive_count = 0
        for chunk in requested_chunks:
            level = chunk.get("classification", ClassificationLevel.PUBLIC)
            # Kita hanya peduli pada data yang sangat sensitif
            if level in [ClassificationLevel.HIGHLY_CONFIDENTIAL, ClassificationLevel.RAW_SECRET]:
                self._history[user_id].append(level)
                sensitive_count += 1

        # Bersihkan riwayat lama agar tidak menyimpan selamanya (misal: hanya cek 10 akses terakhir)
        self._history[user_id] = self._history[user_id][-10:]
        
        total_sensitive_recent = sum(
            1 for level in self._history[user_id] 
            if level in [ClassificationLevel.HIGHLY_CONFIDENTIAL, ClassificationLevel.RAW_SECRET]
        )

        if total_sensitive_recent > self.MAX_SENSITIVE_ACCESSES:
            logger.warning(f"SECURITY ALERT: User {user_id} terdeteksi melakukan Cumulative Disclosure Attack!")
            raise DisclosureRiskError(
                "Akses diblokir: Anda telah mengakses terlalu banyak informasi sensitif dalam waktu singkat. "
                "Pola ini terdeteksi sebagai upaya ekstraksi data rahasia."
            )

# Instance global untuk digunakan di seluruh aplikasi
disclosure_ledger = DisclosureLedger()
