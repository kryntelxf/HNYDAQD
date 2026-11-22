import pytest

from hnydaqd.dlp.output import (
    DLPViolationError,
    enforce_output_policy,
    scan_and_redact,
)


def test_api_key_is_redacted() -> None:
    text = "Gunakan kunci ini: sk-abcdefghijklmnopqrstuvwxyz1234 untuk akses."
    redacted, violations = scan_and_redact(text)
    assert "sk-abcdefghijklmnopqrstuvwxyz1234" not in redacted
    assert "[REDACTED_API_KEY]" in redacted
    assert len(violations) == 1


def test_aws_key_is_redacted() -> None:
    text = "Kredensial: AKIAIOSFODNN7EXAMPLE"
    redacted, violations = scan_and_redact(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED_AWS_KEY]" in redacted


def test_recipe_line_is_redacted() -> None:
    text = "Tentu, ini resepnya: resep: Bahan A 50%, Bahan B 30%, suhu 500C."
    redacted, violations = scan_and_redact(text)
    assert "[REDACTED_RECIPE]" in redacted


def test_process_parameters_are_redacted() -> None:
    text = "Prosesnya adalah 500 derajat C selama 30 menit."
    redacted, violations = scan_and_redact(text)
    assert "[REDACTED_PROCESS_PARAMS]" in redacted


def test_clean_text_is_untouched() -> None:
    text = "Halo, saya siap membantu pertanyaan Anda."
    redacted, violations = scan_and_redact(text)
    assert redacted == text
    assert len(violations) == 0


def test_strict_mode_blocks_violation() -> None:
    text = "Kunci: sk-abcdefghijklmnopqrstuvwxyz1234"
    with pytest.raises(DLPViolationError):
        enforce_output_policy(text, strict=True)


def test_non_strict_mode_redacts_but_allows() -> None:
    text = "Kunci: sk-abcdefghijklmnopqrstuvwxyz1234"
    result = enforce_output_policy(text, strict=False)
    assert "sk-abcdefghijklmnopqrstuvwxyz1234" not in result
    assert "[REDACTED_API_KEY]" in result
