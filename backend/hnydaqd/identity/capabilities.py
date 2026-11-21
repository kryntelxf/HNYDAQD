import logging

from hnydaqd.config import CLASSIFICATION_RANK, ClassificationLevel
from hnydaqd.identity.roles import ROLE_MAX_CLEARANCE, UserRole

logger = logging.getLogger(__name__)


class AccessDeniedError(Exception):
    """Dilempar ketika user mencoba mengakses data di luar wewenangnya."""


def check_capability(user_role: UserRole, data_level: ClassificationLevel) -> bool:
    """
    Memeriksa apakah role user memiliki izin untuk melihat level klasifikasi data.
    Jika tidak, raise AccessDeniedError.
    """
    max_allowed = ROLE_MAX_CLEARANCE.get(user_role)

    if max_allowed is None:
        logger.warning("Akses ditolak: Role %s tidak dikenal.", user_role)
        raise AccessDeniedError("Role pengguna tidak valid.")

    user_rank = CLASSIFICATION_RANK[max_allowed]
    data_rank = CLASSIFICATION_RANK[data_level]

    if data_rank > user_rank:
        logger.warning(
            "Akses ditolak: Role %s (maks %s) mencoba mengakses data %s.",
            user_role.value,
            max_allowed.value,
            data_level.value,
        )
        raise AccessDeniedError(
            f"Role {user_role.value} tidak diizinkan mengakses data berlevel {data_level.value}."
        )

    return True
