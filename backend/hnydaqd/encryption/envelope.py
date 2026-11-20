import base64
import logging
import os

logger = logging.getLogger(__name__)


class EncryptionError(Exception):
    """Raised when encryption or decryption fails."""


class EnvelopeEncryption:
    """AES-256-GCM envelope encryption.

    Runtime dependency: `cryptography`. This is declared in
    `backend/hnydaqd/requirements.txt`, not in the Onyx `pyproject.toml`
    (which uses `package = false` and does not provide `cryptography`).
    The import is lazy so that other HNYDAQD modules do not fail to import
    when `cryptography` is missing from a partial environment.
    """

    def __init__(self, master_key_hex: str) -> None:
        try:
            self.key = bytes.fromhex(master_key_hex)
        except ValueError as e:
            logger.error("Invalid hex key: %s", e)
            raise EncryptionError("Invalid encryption key hex.") from e

        if len(self.key) != 32:
            raise EncryptionError(
                "Key must be 32 bytes (64 hex characters)."
            )

        self._aesgcm = self._build_aesgcm(self.key)

    @staticmethod
    def _build_aesgcm(key: bytes):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ModuleNotFoundError as e:
            raise EncryptionError(
                "The 'cryptography' package is required at runtime for "
                "HNYDAQD envelope encryption."
            ) from e
        return AESGCM(key)

    def encrypt(self, plaintext: str) -> str:
        if not plaintext:
            return ""
        try:
            nonce = os.urandom(12)
            ciphertext = self._aesgcm.encrypt(
                nonce, plaintext.encode("utf-8"), None
            )
            return base64.b64encode(nonce + ciphertext).decode("utf-8")
        except Exception as e:
            logger.error("Encryption failed: %s", e)
            raise EncryptionError("Failed to encrypt data.") from e

    def decrypt(self, encrypted_b64: str) -> str:
        if not encrypted_b64:
            return ""
        try:
            combined = base64.b64decode(encrypted_b64)
            nonce, ciphertext = combined[:12], combined[12:]
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8")
        except Exception as e:
            logger.error("Decryption failed: %s", e)
            raise EncryptionError(
                "Failed to decrypt data. Key may be wrong or data corrupt."
            ) from e
