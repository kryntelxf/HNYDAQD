import logging
from typing import Any, Dict, List

from hnydaqd.config import CLASSIFICATION_RANK, ClassificationLevel
from hnydaqd.disclosure.ledger import disclosure_ledger
from hnydaqd.identity.capabilities import check_capability
from hnydaqd.identity.roles import ROLE_MAX_CLEARANCE, UserRole

logger = logging.getLogger(__name__)


class ContextGateBlockedError(Exception):
    """Dilempar ketika context diblokir oleh kebijakan keamanan."""


class ContextGate:
    def __init__(self, user_role: UserRole) -> None:
        self.user_role = user_role
        # Level maksimal diambil dari matriks role
        self.max_allowed_level = ROLE_MAX_CLEARANCE.get(
            user_role, ClassificationLevel.PUBLIC
        )

    def authorize_context(
        self, chunks: List[Dict[str, Any]], user_id: str = "anonymous"
    ) -> List[Dict[str, Any]]:
        if not chunks:
            return []

        # 1. Cek Cumulative Disclosure (Ledger)
        disclosure_ledger.record_and_verify(user_id, chunks)

        # 2. Cek Batas Klasifikasi berdasarkan Role
        allowed_chunks = []

        for chunk in chunks:
            chunk_level = chunk.get("classification", ClassificationLevel.RAW_SECRET)

            # Cek apakah role user diizinkan untuk level data ini
            try:
                check_capability(self.user_role, chunk_level)
            except Exception:
                logger.warning(
                    "BLOCKED by Role: Chunk %s melebihi wewenang role %s.",
                    chunk.get("id", "unknown"),
                    self.user_role.value,
                )
                continue

            allowed_chunks.append(chunk)

        return allowed_chunks
