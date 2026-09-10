import subprocess
import sys
from pathlib import Path

BUMP_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "bump_version.py"

PROJECT_FIXTURE = """\
[build-system]
requires = ["setuptools>=70", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "sentinelclaw"
version = "0.1.0"
description = "Local defensive cybersecurity analysis CLI."

[tool.ruff]
line-length = 100
"""


def run_bump(
    *args: str,
    pyproject: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(BUMP_SCRIPT),
            "--pyproject",
            str(pyproject),
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def write_fixture(
    tmp_path,
) -> Path:
    pyproject = tmp_path / "pyproject.toml"

    pyproject.write_text(PROJECT_FIXTURE)

    return pyproject


def test_patch_bump_prints_and_updates(
    tmp_path,
) -> None:
    pyproject = write_fixture(tmp_path)

    result = run_bump(
        "--patch",
        pyproject=pyproject,
    )

    assert result.returncode == 0

    assert result.stdout.strip() == "0.1.0 -> 0.1.1"

    assert 'version = "0.1.1"' in pyproject.read_text()


def test_minor_bump_resets_patch(
    tmp_path,
) -> None:
    pyproject = write_fixture(tmp_path)

    result = run_bump(
        "--minor",
        pyproject=pyproject,
    )

    assert result.returncode == 0

    assert result.stdout.strip() == "0.1.0 -> 0.2.0"


def test_major_bump_resets_minor_and_patch(
    tmp_path,
) -> None:
    pyproject = write_fixture(tmp_path)

    result = run_bump(
        "--major",
        pyproject=pyproject,
    )

    assert result.returncode == 0

    assert result.stdout.strip() == "0.1.0 -> 1.0.0"


def test_explicit_target_version(
    tmp_path,
) -> None:
    pyproject = write_fixture(tmp_path)

    result = run_bump(
        "2.5.0",
        pyproject=pyproject,
    )

    assert result.returncode == 0

    assert result.stdout.strip() == "0.1.0 -> 2.5.0"


def test_preserves_rest_of_file(
    tmp_path,
) -> None:
    pyproject = write_fixture(tmp_path)

    result = run_bump(
        "--patch",
        pyproject=pyproject,
    )

    assert result.returncode == 0

    content = pyproject.read_text()

    assert 'description = "Local defensive cybersecurity analysis CLI."' in content

    assert "[tool.ruff]" in content

    assert "line-length = 100" in content


def test_rejects_invalid_target(
    tmp_path,
) -> None:
    pyproject = write_fixture(tmp_path)

    result = run_bump(
        "v2.0",
        pyproject=pyproject,
    )

    assert result.returncode != 0

    assert "invalid version" in result.stderr


def test_rejects_missing_project_version(
    tmp_path,
) -> None:
    pyproject = tmp_path / "pyproject.toml"

    pyproject.write_text("[tool.ruff]\nline-length = 100\n")

    result = run_bump(
        "--patch",
        pyproject=pyproject,
    )

    assert result.returncode != 0

    assert "version" in result.stderr


def test_invalid_mode_flags_rejected(
    tmp_path,
) -> None:
    pyproject = write_fixture(tmp_path)

    result = run_bump(
        "--patch",
        "--minor",
        pyproject=pyproject,
    )

    assert result.returncode != 0
