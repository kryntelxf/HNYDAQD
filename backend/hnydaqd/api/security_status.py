from fastapi import APIRouter
from pydantic import BaseModel

from hnydaqd.audit.sink import default_audit_sink
from hnydaqd.config import CLASSIFICATION_RANK
from hnydaqd.providers.router import PROVIDER_MAX_LEVEL

router = APIRouter(prefix="/hnydaqd", tags=["hnydaqd-security"])


class AuditSummary(BaseModel):
    total_events: int
    integrity_ok: bool


class ClassificationSummary(BaseModel):
    level: str
    rank: int


class ProviderSummary(BaseModel):
    provider: str
    max_classification: str


class SecurityStatusResponse(BaseModel):
    audit: AuditSummary
    classifications: list[ClassificationSummary]
    providers: list[ProviderSummary]


@router.get("/status", response_model=SecurityStatusResponse)
def get_security_status() -> SecurityStatusResponse:
    """Ringkasan status keamanan HNYDAQD untuk dashboard."""
    sink = default_audit_sink
    try:
        integrity_ok = sink.verify_integrity()
    except Exception:
        integrity_ok = False

    return SecurityStatusResponse(
        audit=AuditSummary(
            total_events=sink.count(),
            integrity_ok=integrity_ok,
        ),
        classifications=[
            ClassificationSummary(level=level.value, rank=rank)
            for level, rank in CLASSIFICATION_RANK.items()
        ],
        providers=[
            ProviderSummary(
                provider=provider.value,
                max_classification=level.value,
            )
            for provider, level in PROVIDER_MAX_LEVEL.items()
        ],
    )
