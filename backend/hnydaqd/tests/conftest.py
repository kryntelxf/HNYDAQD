import subprocess
import sys


def _ensure_installed(packages: list[str]) -> None:
    """Ensures required runtime packages are available before any test runs.

    This exists because the Onyx upstream repository does not declare
    `cryptography` (or the test-only HTTP/FastAPI deps) as dependencies. It
    uses `package = false` and overrides only version ranges. HNYDAQD's
    `envelope.py` requires `cryptography` at runtime, and its API tests
    require `httpx` + `fastapi` via `TestClient`. All must be present in
    any environment that imports those modules.
    """
    for package in packages:
        module_name = package.replace("-", "_")
        try:
            __import__(module_name)
        except ModuleNotFoundError:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", package]
            )


_ensure_installed(["cryptography", "httpx", "fastapi"])ography_installed
