import logging
from dataclasses import dataclass

from hnydaqd.config import ClassificationLevel
from hnydaqd.ingestion.validation import (
    classify_document,
    compute_document_hash,
    validate_file,
)

logger = logging.getLogger(__name__)


@dataclass
class IngestionResult:
    filename: str
    size_bytes: int
    content_hash: str
    classification: ClassificationLevel
    accepted: bool = True


def process_upload(filename: str, content: bytes) -> IngestionResult:
    """
    Pipeline utama: validasi -> hash -> klasifikasi.
    Melempar IngestionError jika gagal validasi.
    """
    validate_file(filename, len(content))
    doc_hash = compute_document_hash(content)
    classification = classify_document(filename)

    logger.info(
        "Dokumen '%s' (%d bytes) diterima dengan hash %s dan klasifikasi %s.",
        filename,
        len(content),
        doc_hash[:12] + "...",
        classification.value,
    )

    return IngestionResult(
        filename=filename,
        size_bytes=len(content),
        content_hash=doc_hash,
        classification=classification,
  )
