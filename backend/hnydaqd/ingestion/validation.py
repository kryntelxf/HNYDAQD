import hashlib
import logging
import os
from typing import Optional

from hnydaqd.config import ClassificationLevel

logger = logging.getLogger(__name__)

# Format yang diizinkan (berdasarkan audit baseline: PDF, DOCX, PPTX, EPUB, HTML, TXT)
ALLOWED_EXTENSIONS = {
    ".pdf", ".docx", ".pptx", ".epub", ".html", ".htm", ".txt", ".md"
}

# Batas ukuran file: 50 MB
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024


class IngestionError(Exception):
    """Dilempar ketika dokumen gagal divalidasi."""


def validate_file(filename: str, file_size_bytes: int) -> None:
    """Memvalidasi nama file dan ukuran file sebelum diproses."""
    if file_size_bytes <= 0:
        raise IngestionError("File kosong tidak diizinkan.")

    if file_size_bytes > MAX_FILE_SIZE_BYTES:
        raise IngestionError(
            f"Ukuran file {file_size_bytes} byte melebihi batas "
            f"{MAX_FILE_SIZE_BYTES} byte (50 MB)."
        )

    ext = os.path.splitext(filename.lower())[1]
    if ext not in ALLOWED_EXTENSIONS:
        logger.warning(
            "File ditolak: ekstensi %s tidak diizinkan.", ext
        )
        raise IngestionError(
            f"Ekstensi file '{ext}' tidak diizinkan. "
            f"Hanya {', '.join(sorted(ALLOWED_EXTENSIONS))}."
        )


def compute_document_hash(content: bytes) -> str:
    """Menghitung SHA-256 hash untuk audit (bukti dokumen tidak berubah)."""
    return hashlib.sha256(content).hexdigest()


def classify_document(
    filename: str, content_preview: Optional[str] = None
) -> ClassificationLevel:
    """
    Menentukan klasifikasi awal dokumen.
    Default aman: RAW_SECRET. Bisa diturunkan manual oleh admin.
    """
    # Jika ada indikator publik di nama file (mis. "public-", "demo-"), turunkan
    lower_name = filename.lower()
    if "public" in lower_name or "demo" in lower_name:
        return ClassificationLevel.PUBLIC

    return ClassificationLevel.RAW_SECRET
