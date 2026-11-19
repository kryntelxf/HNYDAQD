import pytest

from hnydaqd.config import ClassificationLevel
from hnydaqd.disclosure.ledger import DisclosureLedger, DisclosureRiskError


def test_cumulative_disclosure_blocks_after_threshold() -> None:
    ledger = DisclosureLedger()
    user_id = "user_123"

    # Simulasi pertanyaan 1: Bahan A (Aman)
    chunks_1 = [{"id": "1", "classification": ClassificationLevel.RAW_SECRET}]
    ledger.record_and_verify(user_id, chunks_1)  # Lolos

    # Simulasi pertanyaan 2: Suhu (Aman)
    chunks_2 = [{"id": "2", "classification": ClassificationLevel.RAW_SECRET}]
    ledger.record_and_verify(user_id, chunks_2)  # Lolos

    # Simulasi pertanyaan 3: Durasi (Aman)
    chunks_3 = [{"id": "3", "classification": ClassificationLevel.RAW_SECRET}]
    ledger.record_and_verify(user_id, chunks_3)  # Lolos

    # Simulasi pertanyaan 4: Waktu (BLOKIR! Karena sudah 4 kali akses rahasia)
    chunks_4 = [{"id": "4", "classification": ClassificationLevel.RAW_SECRET}]

    with pytest.raises(DisclosureRiskError):
        ledger.record_and_verify(user_id, chunks_4)


def test_cumulative_disclosure_ignores_public_data() -> None:
    ledger = DisclosureLedger()
    user_id = "user_456"

    # Akses 10 kali data PUBLIC (Aman, tidak boleh diblokir)
    for i in range(10):
        chunks = [{"id": str(i), "classification": ClassificationLevel.PUBLIC}]
        ledger.record_and_verify(user_id, chunks)
