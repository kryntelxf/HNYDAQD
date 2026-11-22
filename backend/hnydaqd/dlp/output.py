import logging
import re
from typing import List, Tuple

logger = logging.getLogger(__name__)


class DLPViolationError(Exception):
    """Dilempar ketika output AI melanggar kebijakan DLP."""
    pass


# Pola rahasia yang harus disensor (regex sederhana sebagai baseline)
SENSITIVE_PATTERNS = [
    # API key umum (OpenAI sk-, AWS AKIA, dll.)
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "[REDACTED_API_KEY]"),
    (re.compile(r"AKIA[A-Z0-9]{16}"), "[REDACTED_AWS_KEY]"),
    # Format resep kimia eksplisit: "formula: ...", "resep: ..."
    (re.compile(r"(?i)(resep|formula|recipe)\s*[:=]\s*[^\n]{10,}"), "[REDACTED_RECIPE]"),
    # Suhu + durasi + konsentrasi yang mencurigakan dalam satu kalimat
    (
        re.compile(
            r"(?i)(\d{2,4}\s*(°C|derajat|C)\b.{0,50}\d+\s*(menit|jam|detik|min|hour))"
        ),
        "[REDACTED_PROCESS_PARAMS]",
    ),
]


def scan_and_redact(text: str) -> Tuple[str, List[str]]:
    """
    Memindai teks AI, mengembalikan (teks_yang_sudah_disensor, daftar_violasi).
    Tidak melempar error; hanya menyensor.
    """
    violations: List[str] = []
    redacted = text

    for pattern, replacement in SENSITIVE_PATTERNS:
        if pattern.search(redacted):
            violations.append(pattern.pattern)
            redacted = pattern.sub(replacement, redacted)

    if violations:
        logger.warning(
            "DLP menyensor %d pola sensitif pada output AI.", len(violations)
        )

    return redacted, violations


def enforce_output_policy(text: str, strict: bool = False) -> str:
    """
    Jika strict=True dan ada pelanggaran, lempar error.
    Jika strict=False (default), sensor dan lanjutkan.
    """
    redacted, violations = scan_and_redact(text)

    if strict and violations:
        raise DLPViolationError(
            f"Output AI diblokir: {len(violations)} pola sensitif terdeteksi."
        )

    return redacted
