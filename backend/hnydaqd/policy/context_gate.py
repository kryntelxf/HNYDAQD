import logging
from typing import List, Dict, Any
from hnydaqd.config import ClassificationLevel, CLASSIFICATION_RANK
from hnydaqd.disclosure.ledger import disclosure_ledger

logger = logging.getLogger(__name__)

class ContextGateBlockedError(Exception):
    """Dilempar ketika context diblokir oleh kebijakan keamanan."""
    pass

class ContextGate:
    def __init__(self, max_allowed_level: ClassificationLevel):
        self.max_allowed_level = max_allowed_level

    def authorize_context(
        self, chunks: List[Dict[str, Any]], user_id: str = "anonymous"
    ) -> List[Dict[str, Any]]:
        if not chunks:
            return []

        # 1. Cek Cumulative Disclosure (Ledger)
        # Ini akan melempar error jika user terdeteksi mencurigakan
        disclosure_ledger.record_and_verify(user_id, chunks)

        # 2. Cek Batas Klasifikasi per Chunk
        allowed_chunks = []
        max_rank = CLASSIFICATION_RANK[self.max_allowed_level]

        for chunk in chunks:
            chunk_level = chunk.get(
                "classification", ClassificationLevel.RAW_SECRET
            )

            if CLASSIFICATION_RANK[chunk_level] > max_rank:
                logger.warning(
                    f"BLOCKED: Chunk {chunk.get('id', 'unknown')} melebihi batas klasifikasi."
                )
                continue

            allowed_chunks.append(chunk)

        return allowed_chunks
