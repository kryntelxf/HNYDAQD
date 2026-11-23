import subprocess
import sys


def _ensure_installed(packages: list[str]) -> None:
    """Ensures the given packages are importable, installing them if not."""
    for package in packages:
        module = package.replace("-", "_")
        try:
            __import__(module)
        except ModuleNotFoundError:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", package]
            )


_ensure_installed(["cryptography", "httpx", "fastapi"])
