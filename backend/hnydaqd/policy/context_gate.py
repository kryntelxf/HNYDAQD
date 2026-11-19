import pytest

from hnydaqd.encryption.envelope import EncryptionError, EnvelopeEncryption

TEST_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def test_encryption_roundtrip() -> None:
    crypto = EnvelopeEncryption(TEST_KEY)
    original_text = "Resep Rahasia: Bahan A + Bahan B pada suhu 500 derajat."

    encrypted = crypto.encrypt(original_text)
    assert encrypted != original_text
    assert len(encrypted) > 0

    decrypted = crypto.decrypt(encrypted)
    assert decrypted == original_text


def test_encryption_fails_with_wrong_key() -> None:
    crypto1 = EnvelopeEncryption(TEST_KEY)
    crypto2 = EnvelopeEncryption(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )

    encrypted = crypto1.encrypt("Data Sangat Rahasia")

    with pytest.raises(EncryptionError):
        crypto2.decrypt(encrypted)
