from enum import Enum

class ClassificationLevel(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    HIGHLY_CONFIDENTIAL = "HIGHLY_CONFIDENTIAL"
    RAW_SECRET = "RAW_SECRET"

# Urutan prioritas (semakin tinggi, semakin ketat)
CLASSIFICATION_RANK = {
    ClassificationLevel.PUBLIC: 0,
    ClassificationLevel.INTERNAL: 1,
    ClassificationLevel.CONFIDENTIAL: 2,
    ClassificationLevel.HIGHLY_CONFIDENTIAL: 3,
    ClassificationLevel.RAW_SECRET: 4,
}
