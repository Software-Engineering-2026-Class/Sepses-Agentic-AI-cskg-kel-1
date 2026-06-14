"""Tests for QLever setup/start guard behavior."""

from pathlib import Path
from unittest.mock import patch

from src.sparql.qlever_setup import qlever_index_exists, start_endpoint


def test_qlever_index_exists_requires_core_artifacts(tmp_path: Path):
    dataset = "sepses-cskg"
    required = [
        "index.spo",
        "index.pos",
        "index.ops",
        "meta-data.json",
    ]
    for suffix in required:
        (tmp_path / f"{dataset}.{suffix}").write_text("ok", encoding="utf-8")

    assert qlever_index_exists(base_dir=tmp_path) is True

    (tmp_path / f"{dataset}.index.ops").unlink()

    assert qlever_index_exists(base_dir=tmp_path) is False


def test_start_endpoint_does_not_launch_without_index(tmp_path: Path):
    qleverfile = tmp_path / "Qleverfile"
    qleverfile.write_text("", encoding="utf-8")

    with patch("src.sparql.qlever_setup.subprocess.run") as run:
        assert start_endpoint(qleverfile_path=qleverfile) is False

    run.assert_not_called()
