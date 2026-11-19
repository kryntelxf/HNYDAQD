from hnydaqd.config import ClassificationLevel
from hnydaqd.policy.context_gate import ContextGate


def test_context_gate_blocks_raw_secret() -> None:
    gate = ContextGate(max_allowed_level=ClassificationLevel.INTERNAL)

    chunks = [
        {
            "id": "1",
            "text": "Bahan A dan Bahan B",
            "classification": ClassificationLevel.INTERNAL,
        },
        {
            "id": "2",
            "text": "Suhu 500 derajat",
            "classification": ClassificationLevel.RAW_SECRET,
        },
        {
            "id": "3",
            "text": "Info publik",
            "classification": ClassificationLevel.PUBLIC,
        },
    ]

    allowed = gate.authorize_context(chunks, user_id="user_test_1")

    assert len(allowed) == 2
    assert any(c["id"] == "1" for c in allowed)
    assert any(c["id"] == "3" for c in allowed)
    assert not any(c["id"] == "2" for c in allowed), "RAW_SECRET harus diblokir!"


def test_context_gate_allows_confidential_for_private_model() -> None:
    gate = ContextGate(max_allowed_level=ClassificationLevel.CONFIDENTIAL)

    chunks = [
        {
            "id": "1",
            "text": "Data rahasia",
            "classification": ClassificationLevel.CONFIDENTIAL,
        },
        {
            "id": "2",
            "text": "Resep asli",
            "classification": ClassificationLevel.RAW_SECRET,
        },
    ]

    allowed = gate.authorize_context(chunks, user_id="user_test_2")
    assert len(allowed) == 1
    assert allowed[0]["id"] == "1"
