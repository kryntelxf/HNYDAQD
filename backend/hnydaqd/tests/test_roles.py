import pytest

from hnydaqd.config import ClassificationLevel
from hnydaqd.identity.capabilities import AccessDeniedError, check_capability
from hnydaqd.identity.roles import UserRole
from hnydaqd.policy.context_gate import ContextGate


def test_scientist_cannot_access_raw_secret() -> None:
    # Scientist seharusnya dilarang melihat RAW_SECRET
    with pytest.raises(AccessDeniedError):
        check_capability(UserRole.SCIENTIST, ClassificationLevel.RAW_SECRET)


def test_scientist_can_access_confidential() -> None:
    # Scientist boleh melihat CONFIDENTIAL
    assert check_capability(UserRole.SCIENTIST, ClassificationLevel.CONFIDENTIAL) is True


def test_investor_cannot_access_confidential() -> None:
    # Investor hanya boleh lihat INTERNAL ke bawah
    with pytest.raises(AccessDeniedError):
        check_capability(UserRole.INVESTOR, ClassificationLevel.CONFIDENTIAL)


def test_context_gate_filters_based_on_role() -> None:
    # Setup gate untuk Scientist
    gate = ContextGate(user_role=UserRole.SCIENTIST)

    chunks = [
        {"id": "1", "classification": ClassificationLevel.PUBLIC},
        {"id": "2", "classification": ClassificationLevel.CONFIDENTIAL},
        {"id": "3", "classification": ClassificationLevel.RAW_SECRET},  # Harus diblokir
    ]

    allowed = gate.authorize_context(chunks, user_id="scientist_123")

    # Scientist hanya boleh dapat 2 chunk (Public dan Confidential)
    assert len(allowed) == 2
    assert not any(c["id"] == "3" for c in allowed)
