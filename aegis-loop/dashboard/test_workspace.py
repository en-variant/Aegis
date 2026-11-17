import hashlib
from pathlib import Path

import pytest

from dashboard import workspace


def _fixture(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    target = tmp_path / "sample.py"
    target.write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setattr(workspace, "ROOT", tmp_path)
    monkeypatch.setattr(workspace, "EDITABLE_FILES", {"sample.py"})
    return target


def test_preview_does_not_apply_until_explicit_approval(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = _fixture(monkeypatch, tmp_path)
    original = target.read_text(encoding="utf-8")
    checksum = hashlib.sha256(original.encode("utf-8")).hexdigest()
    preview = workspace.preview_change("sample.py", "value = 2\n", checksum)

    assert "-value = 1" in preview["diff"]
    assert "+value = 2" in preview["diff"]
    assert target.read_text(encoding="utf-8") == original
    with pytest.raises(PermissionError, match="Explicit approval"):
        workspace.apply_change(preview["change_id"], approved=False)

    workspace.apply_change(preview["change_id"], approved=True)
    assert target.read_text(encoding="utf-8") == "value = 2\n"


def test_preview_rejects_stale_file_version(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = _fixture(monkeypatch, tmp_path)
    checksum = hashlib.sha256(target.read_bytes()).hexdigest()
    target.write_text("value = 3\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="changed since it was loaded"):
        workspace.preview_change("sample.py", "value = 2\n", checksum)


def test_apply_rejects_file_changed_after_preview(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = _fixture(monkeypatch, tmp_path)
    checksum = hashlib.sha256(target.read_bytes()).hexdigest()
    preview = workspace.preview_change("sample.py", "value = 2\n", checksum)
    target.write_text("value = 3\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="changed after preview"):
        workspace.apply_change(preview["change_id"], approved=True)
    assert target.read_text(encoding="utf-8") == "value = 3\n"
