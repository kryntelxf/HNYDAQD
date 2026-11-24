import pytest

from hnydaqd.config import ClassificationLevel
from hnydaqd.export.policy import ExportDeniedError, ExportRequest, authorize_export
from hnydaqd.identity.roles import UserRole


def test_owner_can_export_within_limits() -> None:
    authorize_export(
        ExportRequest(
            user_role=UserRole.OWNER,
            record_count=5_000,
            highest_classification=ClassificationLevel.CONFIDENTIAL,
            format="csv",
        )
    )


def test_scientist_exceeds_record_limit() -> None:
    with pytest.raises(ExportDeniedError):
        authorize_export(
            ExportRequest(
                user_role=UserRole.SCIENTIST,
                record_count=5_000,  # > 1_000
                highest_classification=ClassificationLevel.CONFIDENTIAL,
                format="csv",
            )
        )


def test_investor_cannot_export_confidential() -> None:
    with pytest.raises(ExportDeniedError):
        authorize_export(
            ExportRequest(
                user_role=UserRole.INVESTOR,
                record_count=50,
                highest_classification=ClassificationLevel.CONFIDENTIAL,
                format="csv",
            )
        )


def test_auditor_cannot_export_anything() -> None:
    with pytest.raises(ExportDeniedError):
        authorize_export(
            ExportRequest(
                user_role=UserRole.AUDITOR,
                record_count=1,
                highest_classification=ClassificationLevel.PUBLIC,
                format="csv",
            )
        )


def test_disallowed_format_rejected() -> None:
    with pytest.raises(ExportDeniedError):
        authorize_export(
            ExportRequest(
                user_role=UserRole.OWNER,
                record_count=10,
                highest_classification=ClassificationLevel.PUBLIC,
                format="exe",
            )
        )


def test_investor_can_export_within_limits() -> None:
    authorize_export(
        ExportRequest(
            user_role=UserRole.INVESTOR,
            record_count=50,
            highest_classification=ClassificationLevel.INTERNAL,
            format="json",
        )
    )
