from fastapi.testclient import TestClient

from hnydaqd.api.security_status import router


def _build_app():
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)
    return app


def test_status_endpoint_returns_ok() -> None:
    client = TestClient(_build_app())
    response = client.get("/hnydaqd/status")
    assert response.status_code == 200
    data = response.json()
    assert "audit" in data
    assert "classifications" in data
    assert "providers" in data


def test_status_endpoint_lists_all_classifications() -> None:
    client = TestClient(_build_app())
    data = client.get("/hnydaqd/status").json()
    levels = {c["level"] for c in data["classifications"]}
    assert "PUBLIC" in levels
    assert "RAW_SECRET" in levels


def test_status_endpoint_lists_three_providers() -> None:
    client = TestClient(_build_app())
    data = client.get("/hnydaqd/status").json()
    providers = {p["provider"] for p in data["providers"]}
    assert "EXTERNAL" in providers
    assert "ENTERPRISE_SAFE" in providers
    assert "PRIVATE" in providers
