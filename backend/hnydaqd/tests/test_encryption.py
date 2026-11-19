import pytest

from hnydaqd.encryption.envelope import EncryptionError, EnvelopeEncryption

# Kunci dummy 32-byte (64 karakter hex) khusus untuk testing
TEST_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def test_encryption_roundtrip():
    # Inisialisasi
    crypto = EnvelopeEncryption(TEST_KEY)
    original_text = "Resep Rahasia: Bahan A + Bahan B pada suhu 500 derajat."

    # Enkripsi
    encrypted = crypto.encrypt(original_text)
    assert encrypted != original_text
    assert len(encrypted) > 0

    # Dekripsi
    decrypted = crypto.decrypt(encrypted)
    assert decrypted == original_text


def test_encryption_fails_with_wrong_key():
    crypto1 = EnvelopeEncryption(TEST_KEY)
    # Kunci berbeda (tapi tetap 32-byte)
    crypto2 = EnvelopeEncryption(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )

    encrypted = crypto1.encrypt("Data Sangat Rahasia")

    # Mencoba mendekripsi dengan kunci yang salah harus gagal (melempar error)
    with pytest.raises(EncryptionError):
        crypto2.decrypt(encrypted)
