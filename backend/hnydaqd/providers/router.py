import logging
from dataclasses import dataclass
from enum import Enum

from hnydaqd.config import CLASSIFICATION_RANK, ClassificationLevel

logger = logging.getLogger(__name__)


class ProviderType(str, Enum):
    EXTERNAL = "EXTERNAL"                # OpenAI, Anthropic, Gemini, dll
    ENTERPRISE_SAFE = "ENTERPRISE_SAFE"  # Provider dengan kontrak privasi khusus
    PRIVATE = "PRIVATE"                  # Model lokal/self-hosted (Ollama, vLLM)


# Batas maksimum klasifikasi data yang boleh dikirim ke provider
PROVIDER_MAX_LEVEL = {
    ProviderType.EXTERNAL: ClassificationLevel.INTERNAL,
    ProviderType.ENTERPRISE_SAFE: ClassificationLevel.CONFIDENTIAL,
    ProviderType.PRIVATE: ClassificationLevel.RAW_SECRET,
}


class ProviderRoutingError(Exception):
    """Dilempar ketika provider tidak diizinkan untuk menerima klasifikasi data tertentu."""
    pass


@dataclass
class RoutingDecision:
    provider: ProviderType
    max_classification: ClassificationLevel


def route_for_classification(data_level: ClassificationLevel) -> RoutingDecision:
    """
    Memilih provider termurah yang masih aman untuk klasifikasi data tertentu.

    Urutan prioritas: EXTERNAL > ENTERPRISE_SAFE > PRIVATE
    (murah -> mahal, tetapi hanya dipilih jika level data masih diizinkan).
    """
    data_rank = CLASSIFICATION_RANK[data_level]

    # Cari provider termurah (paling rendah kapasitasnya) yang masih aman.
    for provider in [
        ProviderType.EXTERNAL,
        ProviderType.ENTERPRISE_SAFE,
        ProviderType.PRIVATE,
    ]:
        max_level = PROVIDER_MAX_LEVEL[provider]
        if CLASSIFICATION_RANK[max_level] >= data_rank:
            logger.info(
                "Data %s dirutekan ke provider %s (max %s).",
                data_level.value,
                provider.value,
                max_level.value,
            )
            return RoutingDecision(provider=provider, max_classification=max_level)

    # Tidak ada provider yang cocok (seharusnya tidak terjadi karena PRIVATE
    # menangani semua level, tapi tetap dijaga untuk keamanan tipe).
    raise ProviderRoutingError(
        f"Tidak ada provider yang diizinkan untuk klasifikasi {data_level.value}."
    )


def assert_provider_allowed(
    provider: ProviderType, data_level: ClassificationLevel
) -> None:
    """
    Memeriksa apakah provider tertentu boleh menerima klasifikasi data tertentu.
    Melempar ProviderRoutingError jika tidak boleh.
    """
    max_level = PROVIDER_MAX_LEVEL.get(provider)
    if max_level is None:
        raise ProviderRoutingError(f"Provider {provider} tidak dikenal.")

    if CLASSIFICATION_RANK[data_level] > CLASSIFICATION_RANK[max_level]:
        logger.warning(
            "BLOKIR: Provider %s (max %s) tidak boleh menerima data %s.",
            provider.value,
            max_level.value,
            data_level.value,
        )
        raise ProviderRoutingError(
            f"Provider {provider.value} tidak boleh menerima data {data_level.value}."
    )
