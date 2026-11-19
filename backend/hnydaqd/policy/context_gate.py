import logging
from typing import Any, Dict, List

from hnydaqd.config import CLASSIFICATION_RANK, ClassificationLevel
from hnydaqd.disclosure.ledger import disclosure_ledger

logger = logging.getLogger(__name__)


class ContextGateBlockedError(Exception):
    """Dilempar ketika context diblokir oleh kebijakan keamanan."""


class ContextGate:
    def __init__(self, max_allowed_level: ClassificationLevel) -> None:
        self.max_allowed_level = max_allowed_level

    def authorize_context(
        self, chunks: List[Dict[str, Any]], user_id: str = "anonymous"
    ) -> List[Dict[str, Any]]:
        if not chunks:
            return []

        disclosure_ledger.record_and_verify(user_id, chunks)

        allowed_chunks = []
        max_rank = CLASSIFICATION_RANK[self.max_allowed_level]

        for chunk in chunks:
            chunk_level = chunk.get("classification", ClassificationLevel.RAW_SECRET)

            if CLASSIFICATION_RANK[chunk_level] > max_rank:
                logger.warning(
                    "BLOCKED: Chunk %s melebihi batas klasifikasi.",
                    chunk.get("id", "unknown"),
                )
                continue

            allowed_chunks.append(chunk)

        return allowed_chunks
