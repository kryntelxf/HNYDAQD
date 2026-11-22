import pytest

from hnydaqd.config import ClassificationLevel
from hnydaqd.ingestion.pipeline import process_upload
from hnydaqd.ingestion.validation import IngestionError, validate_file


def test_valid_pdf_accepted() -> None:
    result = process_upload("resep.pdf", b"%PDF-1.4 dummy content")
    assert result.accepted is True
    assert result.classification == ClassificationLevel.RAW_SECRET
    assert len(result.content_hash) == 64  # SHA-256 hex


def test_valid_docx_accepted() -> None:
    result = process_upload("laporan.docx", b"PK dummy docx content")
    assert result.accepted is True


def test_executable_rejected() -> None:
    with pytest.raises(IngestionError):
        process_upload("malware.exe", b"MZ dummy executable")


def test_shell_script_rejected() -> None:
    with pytest.raises(IngestionError):
        validate_file("run.sh", 100)


def test_empty_file_rejected() -> None:
    with pytest.raises(IngestionError):
        validate_file("empty.pdf", 0)


def test_oversized_file_rejected() -> None:
    # 51 MB > 50 MB limit
    with pytest.raises(IngestionError):
        validate_file("big.pdf", 51 * 1024 * 1024)


def test_public_file_classified_correctly() -> None:
    result = process_upload("public-brochure.pdf", b"%PDF-1.4 dummy")
    assert result.classification == ClassificationLevel.PUBLIC
