from enum import Enum

from hnydaqd.config import ClassificationLevel


class UserRole(str, Enum):
    OWNER = "OWNER"
    SCIENTIST = "SCIENTIST"
    INVESTOR = "INVESTOR"
    AUDITOR = "AUDITOR"


# Batas maksimal data yang boleh diakses oleh masing-masing role
ROLE_MAX_CLEARANCE = {
    # Owner punya akses tertinggi, TAPI tidak otomatis bisa bypass tanpa audit
    UserRole.OWNER: ClassificationLevel.RAW_SECRET,
    # Scientist hanya boleh melihat data terklasifikasi hingga Confidential
    # (Dilarang melihat RAW_SECRET / resep asli)
    UserRole.SCIENTIST: ClassificationLevel.CONFIDENTIAL,
    # Investor hanya boleh melihat data publik dan internal (untuk demo/pitch)
    UserRole.INVESTOR: ClassificationLevel.INTERNAL,
    # Auditor hanya bisa melihat log, bukan data rahasia
    UserRole.AUDITOR: ClassificationLevel.PUBLIC,
}
