import logging
from dataclasses import dataclass

from hnydaqd.config import CLASSIFICATION_RANK, ClassificationLevel
from hnydaqd.identity.roles import UserRole

logger = logging.getLogger(__name__)


class ExportDeniedError(Exception):
    """Dilempar ketika user mencoba mengekspor data yang tidak diizinkan."""

    pass


# Batas maksimum baris/dokumen yang boleh diekspor per role
EXPORT_LIMITS = {
    UserRole.OWNER: 10_000,
    UserRole.SCIENTIST: 1_000,
    UserRole.INVESTOR: 100,
    UserRole.AUDITOR: 0,  # Auditor tidak boleh ekspor data mentah
}

# Batas maksimum klasifikasi yang boleh diekspor per role
EXPORT_MAX_LEVEL = {
    UserRole.OWNER: ClassificationLevel.CONFIDENTIAL,
    UserRole.SCIENTIST: ClassificationLevel.CONFIDENTIAL,
    UserRole.INVESTOR: ClassificationLevel.INTERNAL,
    UserRole.AUDITOR: ClassificationLevel.PUBLIC,
}


@dataclass
class ExportRequest:
    user_role: UserRole
    record_count: int
    highest_classification: ClassificationLevel
    format: str  # "csv", "json", "pdf", etc.


def authorize_export(request: ExportRequest) -> None:
    """
    Memvalidasi permintaan ekspor. Melempar ExportDeniedError jika ditolak.
    """
    # 1. Format harus diizinkan (whitelist)
    allowed_formats = {"csv", "json"}
    if request.format.lower() not in allowed_formats:
        raise ExportDeniedError(
            f"Format '{request.format}' tidak diizinkan. "
            f"Gunakan: {', '.join(sorted(allowed_formats))}."
        )

    # 2. Batas jumlah record
    max_records = EXPORT_LIMITS.get(request.user_role, 0)
    if request.record_count > max_records:
        logger.warning(
            "Ekspor ditolak: role %s meminta %d record (max %d).",
            request.user_role.value,
            request.record_count,
            max_records,
        )
        raise ExportDeniedError(
            f"Role {request.user_role.value} hanya boleh ekspor "
            f"sampai {max_records} record (diminta {request.record_count})."
        )

    # 3. Batas klasifikasi
    max_level = EXPORT_MAX_LEVEL[request.user_role]
    if CLASSIFICATION_RANK[request.highest_classification] > CLASSIFICATION_RANK[max_level]:
        raise ExportDeniedError(
            f"Role {request.user_role.value} tidak boleh ekspor data "
            f"berlevel {request.highest_classification.value}."
        )

    logger.info(
        "Ekspor diizinkan: role=%s, records=%d, level=%s, format=%s",
        request.user_role.value,
        request.record_count,
        request.highest_classification.value,
        request.format,
  )
