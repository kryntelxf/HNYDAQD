import subprocess
import sys


def _ensure_cryptography_installed() -> None:
    """Ensures `cryptography` is available before any test runs.

    This exists because the Onyx upstream repository does not declare
    `cryptography` as a dependency (it uses `package = false` and
    overrides the version range only). HNYDAQD's `envelope.py` requires it
    at runtime, so it must be available in any environment that imports
    that module.
    """
    try:
        import cryptography  # noqa: F401
        return
    except ModuleNotFoundError:
        pass

    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "--quiet", "cryptography"]
    )


_ensure_cryptography_installed()
