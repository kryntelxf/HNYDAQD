import base64
import logging
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


class EncryptionError(Exception):
    """Dilempar ketika terjadi kegagalan enkripsi/dekripsi."""

    pass


class EnvelopeEncryption:
    def __init__(self, master_key_hex: str):
        """
        master_key_hex: 64 karakter hex string (32 bytes) untuk AES-256.
        Kunci ini HARUS disimpan di environment variable, bukan di source code.
        """
        try:
            self.key = bytes.fromhex(master_key_hex)
            if len(self.key) != 32:
                raise ValueError("Kunci harus 32 bytes (64 karakter hex).")
            self.aesgcm = AESGCM(self.key)
        except Exception as e:
            logger.error("Gagal inisialisasi enkripsi: %s", e)
            raise EncryptionError("Konfigurasi kunci enkripsi tidak valid.")

    def encrypt(self, plaintext: str) -> str:
        """Mengenkripsi teks dan mengembalikan format base64 (nonce + ciphertext)."""
        if not plaintext:
            return ""

        try:
            nonce = os.urandom(12)  # Nonce standar 96-bit untuk GCM
            ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

            # Gabungkan nonce dan ciphertext, lalu encode ke base64
            combined = nonce + ciphertext
            return base64.b64encode(combined).decode("utf-8")
        except Exception as e:
            logger.error("Enkripsi gagal: %s", e)
            raise EncryptionError("Gagal mengenkripsi data.")

    def decrypt(self, encrypted_b64: str) -> str:
        """Mendekripsi teks base64 kembali ke teks asli."""
        if not encrypted_b64:
            return ""

        try:
            combined = base64.b64decode(encrypted_b64)
            nonce = combined[:12]
            ciphertext = combined[12:]

            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8")
        except Exception as e:
            logger.error("Dekripsi gagal: %s", e)
            raise EncryptionError(
                "Gagal mendekripsi data. Kunci mungkin salah atau data rusak."
            )
