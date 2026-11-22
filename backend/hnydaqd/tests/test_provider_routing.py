import pytest

from hnydaqd.config import ClassificationLevel
from hnydaqd.providers.router import (
    ProviderRoutingError,
    ProviderType,
    assert_provider_allowed,
    route_for_classification,
)


def test_public_data_routes_to_external() -> None:
    decision = route_for_classification(ClassificationLevel.PUBLIC)
    assert decision.provider == ProviderType.EXTERNAL


def test_internal_data_routes_to_external() -> None:
    decision = route_for_classification(ClassificationLevel.INTERNAL)
    assert decision.provider == ProviderType.EXTERNAL


def test_confidential_data_routes_to_enterprise_safe() -> None:
    decision = route_for_classification(ClassificationLevel.CONFIDENTIAL)
    assert decision.provider == ProviderType.ENTERPRISE_SAFE


def test_raw_secret_routes_to_private() -> None:
    decision = route_for_classification(ClassificationLevel.RAW_SECRET)
    assert decision.provider == ProviderType.PRIVATE


def test_external_provider_cannot_receive_raw_secret() -> None:
    with pytest.raises(ProviderRoutingError):
        assert_provider_allowed(ProviderType.EXTERNAL, ClassificationLevel.RAW_SECRET)


def test_private_provider_can_receive_anything() -> None:
    # Tidak boleh raise error
    assert_provider_allowed(ProviderType.PRIVATE, ClassificationLevel.RAW_SECRET)
    assert_provider_allowed(ProviderType.PRIVATE, ClassificationLevel.PUBLIC)
