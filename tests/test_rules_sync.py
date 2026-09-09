import subprocess
import sys
from pathlib import Path

SYNC_SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "sync_rules.py"
)


def run_sync(
    *args: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SYNC_SCRIPT),
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_check_reports_drift(
    tmp_path,
) -> None:
    source = tmp_path / "rules"
    destination = tmp_path / "packaged" / "rules"
    source.mkdir()
    destination.mkdir(
        parents=True
    )

    (source / "a.yaml").write_text(
        "rules: []\n"
    )
    (destination / "a.yaml").write_text(
        "rules: []\n  drifted\n"
    )

    result = run_sync(
        "--check",
        "--source",
        str(source),
        "--dest",
        str(destination),
    )

    assert result.returncode == 1
    assert "out of sync" in result.stdout
    assert "a.yaml" in result.stdout


def test_check_passes_when_identical(
    tmp_path,
) -> None:
    source = tmp_path / "rules"
    destination = tmp_path / "packaged" / "rules"
    source.mkdir()
    destination.mkdir(
        parents=True
    )

    content = "rules: []\n"
    (source / "a.yaml").write_text(
        content
    )
    (destination / "a.yaml").write_text(
        content
    )

    result = run_sync(
        "--check",
        "--source",
        str(source),
        "--dest",
        str(destination),
    )

    assert result.returncode == 0
    assert "in sync" in result.stdout


def test_sync_makes_copies_identical(
    tmp_path,
) -> None:
    source = tmp_path / "rules"
    destination = tmp_path / "packaged" / "rules"
    source.mkdir()
    destination.mkdir(
        parents=True
    )

    (source / "a.yaml").write_text(
        "rules: [one]\n"
    )
    (destination / "a.yaml").write_text(
        "rules: [two]\n"
    )
    (source / "b.yaml").write_text(
        "rules: [three]\n"
    )
    (destination / "only_dest.yaml").write_text(
        "rules: [four]\n"
    )

    sync_result = run_sync(
        "--sync",
        "--source",
        str(source),
        "--dest",
        str(destination),
    )

    assert sync_result.returncode == 0
    assert not (destination / "only_dest.yaml").exists()
    assert (destination / "a.yaml").read_text() == "rules: [one]\n"
    assert (destination / "b.yaml").read_text() == "rules: [three]\n"

    check_result = run_sync(
        "--check",
        "--source",
        str(source),
        "--dest",
        str(destination),
    )

    assert check_result.returncode == 0


def test_missing_source_directory_fails(
    tmp_path,
) -> None:
    destination = tmp_path / "packaged" / "rules"
    destination.mkdir(
        parents=True
    )

    result = run_sync(
        "--check",
        "--source",
        str(tmp_path / "nope"),
        "--dest",
        str(destination),
    )

    assert result.returncode == 2
    assert "does not exist" in result.stdout


def test_sync_creates_missing_destination(
    tmp_path,
) -> None:
    source = tmp_path / "rules"
    source.mkdir()

    (source / "a.yaml").write_text(
        "rules: []\n"
    )

    result = run_sync(
        "--sync",
        "--source",
        str(source),
        "--dest",
        str(tmp_path / "packaged"),
    )

    assert result.returncode == 0
    assert (tmp_path / "packaged" / "a.yaml").exists()

def test_check_and_sync_cover_nested_sigma_trees(
    tmp_path,
) -> None:
    source = tmp_path / "rules"
    destination = tmp_path / "packaged" / "rules"
    source.mkdir()
    destination.mkdir(parents=True)

    (source / "sigma" / "windows").mkdir(parents=True)
    (source / "sigma" / "windows" / "rule.yaml").write_text(
        "rules: [nested]\n"
    )

    result = run_sync(
        "--sync",
        "--source",
        str(source),
        "--dest",
        str(destination),
    )

    assert result.returncode == 0

    copied = destination / "sigma" / "windows" / "rule.yaml"

    assert copied.exists()
    assert copied.read_text() == "rules: [nested]\n"

    (source / "sigma" / "windows" / "rule.yaml").write_text(
        "rules: [changed]\n"
    )

    check = run_sync(
        "--check",
        "--source",
        str(source),
        "--dest",
        str(destination),
    )

    assert check.returncode == 1
    assert "sigma/windows/rule.yaml" in check.stdout.replace("\\", "/")
