import logging
from typing import List, Dict, Any
from backend.hnydaqd.config import ClassificationLevel, CLASSIFICATION_RANK

logger = logging.getLogger(__name__)

class ContextGateBlockedError(Exception):
    """Dilempar ketika context diblokir oleh kebijakan keamanan."""
    pass

class ContextGate:
    def __init__(self, max_allowed_level: ClassificationLevel):
        """
        max_allowed_level: Batas maksimal klasifikasi yang boleh dilewatkan.
        Contoh: Jika model AI eksternal, max_allowed_level = INTERNAL.
        """
        self.max_allowed_level = max_allowed_level

    def authorize_context(self, chunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Memfilter chunks. Jika ada chunk yang melebihi batas, chunk tersebut dibuang.
        Jika seluruh request membahayakan, bisa raise ContextGateBlockedError.
        """
        if not chunks:
            return []

        allowed_chunks = []
        max_rank = CLASSIFICATION_RANK[self.max_allowed_level]

        for chunk in chunks:
            # Asumsi: chunk memiliki metadata 'classification'
            chunk_level = chunk.get("classification", ClassificationLevel.RAW_SECRET)
            
            if CLASSIFICATION_RANK[chunk_level] > max_rank:
                logger.warning(f"BLOCKED: Chunk {chunk.get('id', 'unknown')} melebihi batas klasifikasi.")
                continue # Buang chunk ini
            
            allowed_chunks.append(chunk)

        return allowed_chunks
