from hnydaqd.config import ClassificationLevel
from hnydaqd.identity.roles import UserRole
from hnydaqd.policy.context_gate import ContextGate


def test_context_gate_blocks_raw_secret() -> None:
    # Gunakan SCIENTIST sebagai representasi role "Internal" (maks CONFIDENTIAL)
    gate = ContextGate(user_role=UserRole.SCIENTIST)

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
    # Gunakan OWNER sebagai representasi role yang bisa lihat hingga RAW_SECRET
    # (Tapi kita hanya test hingga CONFIDENTIAL di sini)
    gate = ContextGate(user_role=UserRole.OWNER)

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
    # OWNER boleh lihat keduanya
    assert len(allowed) == 2
