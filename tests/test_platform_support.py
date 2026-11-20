from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

from conftest import Harness
from release_proof_mcp import consumer as consumer_module
from test_evidence_package import publish, verify


def _windows_namespace() -> SimpleNamespace:
    return SimpleNamespace(**{**vars(os), "name": "nt"})


def test_windows_package_reader_avoids_directory_descriptors(
    tmp_path: Path, harness: Harness, monkeypatch
) -> None:
    case = publish(harness, tmp_path / "operator")
    monkeypatch.setattr(consumer_module, "os", _windows_namespace())
    real_open = consumer_module.os.open

    def checked_open(path, flags, **kwargs):
        assert "dir_fd" not in kwargs
        return real_open(path, flags)

    monkeypatch.setattr(consumer_module.os, "open", checked_open)

    decision = verify(case)

    assert decision["allow"] is True
    assert decision["reason"] == "OK"


def test_windows_package_root_symlink_is_rejected(
    tmp_path: Path, harness: Harness, monkeypatch
) -> None:
    case = publish(harness, tmp_path / "operator")
    monkeypatch.setattr(consumer_module, "os", _windows_namespace())
    link = tmp_path / "package-link"
    link.symlink_to(case.path, target_is_directory=True)

    decision = consumer_module.verify_evidence_package(link, **case.options)

    assert decision["allow"] is False
    assert decision["reason"] == "PACKAGE_FILE_INVALID"
