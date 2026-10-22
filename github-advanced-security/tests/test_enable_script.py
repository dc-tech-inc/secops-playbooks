"""Run the enablement script in dry-run mode: it must print the calls and change nothing."""

import shutil
import subprocess  # noqa: S404
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "enable-security-features.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash not available")


def _run(*args):
    return subprocess.run([BASH, str(SCRIPT), *args], capture_output=True, text=True, check=False)  # noqa: S603


def test_dry_run_prints_every_call():
    result = _run("example-org/example-repo")
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert out.count("DRY RUN:") == 5
    for endpoint in ("vulnerability-alerts", "automated-security-fixes", "private-vulnerability-reporting"):
        assert f"repos/example-org/example-repo/{endpoint}" in out
    assert "secret_scanning_push_protection" in out
    assert "Nothing changed" in out


@pytest.mark.parametrize("args", [(), ("not a repo",), ("a/b", "--force"), ("a/b", "--apply", "x")])
def test_rejects_bad_arguments(args):
    assert _run(*args).returncode == 2
