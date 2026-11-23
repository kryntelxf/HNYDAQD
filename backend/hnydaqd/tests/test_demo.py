import os
import subprocess
import sys
from pathlib import Path


def test_demo_runs_successfully() -> None:
    """
    Runs the end-to-end demo script and asserts exit code 0.
    This is a smoke test: if the demo crashes, the security pipeline
    is broken in a way unit tests might not catch.
    """
    backend_dir = Path(__file__).resolve().parents[3]  # .../backend

    # Ensure the subprocess can import `hnydaqd` regardless of the parent's
    # environment (CI, local, pytest, etc.).
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        f"{backend_dir}{os.pathsep}{existing_pythonpath}"
        if existing_pythonpath
        else str(backend_dir)
    )

    result = subprocess.run(
        [sys.executable, "-m", "hnydaqd.demo.e2e_demo"],
        cwd=str(backend_dir),
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert result.returncode == 0, (
        f"Demo failed.\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    assert "Integrity: OK" in result.stdout
    assert "SUMMARY" in result.stdout
