import subprocess
import sys


def _ensure_installed(packages: list[str]) -> None:
    """Ensures the given packages are importable, installing them if not.

    HNYDAQD declares `cryptography` as a runtime dependency, but the Onyx
    `pyproject.toml` uses `package = false` and does not include it, so
    each test environment must ensure it is present before tests run.
    `httpx` and `fastapi` are needed by the API tests.
    """
    for package in packages:
        module = package.replace("-", "_")
        try:
            __import__(module)
        except ModuleNotFoundError:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", package]
            )


_ensure_installed(["cryptography", "httpx", "fastapi"])
