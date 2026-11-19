import pytest

from hnydaqd.config import ClassificationLevel
from hnydaqd.disclosure.ledger import DisclosureLedger, DisclosureRiskError


def test_cumulative_disclosure_blocks_after_threshold() -> None:
    ledger = DisclosureLedger()
    user_id = "user_123"

    chunks_1 = [{"id": "1", "classification": ClassificationLevel.RAW_SECRET}]
    ledger.record_and_verify(user_id, chunks_1)

    chunks_2 = [{"id": "2", "classification": ClassificationLevel.RAW_SECRET}]
    ledger.record_and_verify(user_id, chunks_2)

    chunks_3 = [{"id": "3", "classification": ClassificationLevel.RAW_SECRET}]
    ledger.record_and_verify(user_id, chunks_3)

    chunks_4 = [{"id": "4", "classification": ClassificationLevel.RAW_SECRET}]

    with pytest.raises(DisclosureRiskError):
        ledger.record_and_verify(user_id, chunks_4)


def test_cumulative_disclosure_ignores_public_data() -> None:
    ledger = DisclosureLedger()
    user_id = "user_456"

    for i in range(10):
        chunks = [{"id": str(i), "classification": ClassificationLevel.PUBLIC}]
        ledger.record_and_verify(user_id, chunks)
