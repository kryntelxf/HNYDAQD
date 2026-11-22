from hnydaqd.config import ClassificationLevel
from hnydaqd.identity.roles import UserRole
from hnydaqd.identity.session import determine_role
from hnydaqd.policy.service import policy_service


def test_determine_role_admin_is_owner() -> None:
    assert determine_role(is_admin=True, email="x@y.z") == UserRole.OWNER


def test_determine_role_scientist_by_email() -> None:
    assert (
        determine_role(is_admin=False, email="scientist@lab.co")
        == UserRole.SCIENTIST
    )


def test_determine_role_unknown_is_investor() -> None:
    assert determine_role(is_admin=False, email="foo@bar.com") == UserRole.INVESTOR


def test_policy_service_filters_chunks_by_role() -> None:
    chunks = [
        {"id": "1", "classification": ClassificationLevel.PUBLIC},
        {"id": "2", "classification": ClassificationLevel.RAW_SECRET},
    ]
    allowed = policy_service.authorize_and_record(
        user_id="test_user",
        user_role=UserRole.SCIENTIST,
        chunks=chunks,
    )
    assert len(allowed) == 1
    assert allowed[0]["id"] == "1"
