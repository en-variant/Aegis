import difflib
import hashlib
import os
import tempfile
import threading
import time
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
EDITABLE_FILES = {
    "aegis_loop/policy.py",
    "aegis_loop/runtime.py",
}
MAX_FILE_BYTES = 64 * 1024
PREVIEW_TTL_SECONDS = 300
_previews: dict[str, dict[str, str | float]] = {}
_preview_lock = threading.Lock()
_apply_lock = threading.Lock()


def _resolve_editable(path: str) -> Path:
    if path not in EDITABLE_FILES:
        raise ValueError("File is not in the editor allowlist")
    candidate = ROOT / path
    if candidate.is_symlink():
        raise ValueError("Symbolic links are not editable")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(ROOT.resolve()):
        raise ValueError("File must remain inside the Aegis Loop repository")
    if not resolved.is_file():
        raise ValueError("Editor target must be a regular file")
    if resolved.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("File exceeds the editor size limit")
    return resolved


def list_files() -> list[dict[str, str | int]]:
    files = []
    for path in sorted(EDITABLE_FILES):
        target = _resolve_editable(path)
        content = target.read_bytes()
        files.append(
            {
                "path": path,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    return files


def read_file(path: str) -> dict[str, str]:
    target = _resolve_editable(path)
    content = target.read_text(encoding="utf-8")
    return {
        "path": path,
        "content": content,
        "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
    }


def preview_change(path: str, content: str, base_sha256: str) -> dict[str, str]:
    if "\x00" in content:
        raise ValueError("Null bytes are not allowed")
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_FILE_BYTES:
        raise ValueError("Draft exceeds the editor size limit")

    with _apply_lock:
        current = read_file(path)
        if current["sha256"] != base_sha256:
            raise RuntimeError("File changed since it was loaded; reload before previewing")

    diff = "".join(
        difflib.unified_diff(
            current["content"].splitlines(keepends=True),
            content.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )
    change_id = uuid4().hex
    with _preview_lock:
        now = time.monotonic()
        expired = [
            key
            for key, value in _previews.items()
            if now - float(value["created_at"]) > PREVIEW_TTL_SECONDS
        ]
        for key in expired:
            _previews.pop(key, None)
        _previews[change_id] = {
            "path": path,
            "content": content,
            "base_sha256": base_sha256,
            "created_at": now,
        }
    return {"change_id": change_id, "path": path, "diff": diff}


def apply_change(change_id: str, approved: bool) -> dict[str, str]:
    if not approved:
        raise PermissionError("Explicit approval is required to apply this diff")

    with _preview_lock:
        preview = _previews.get(change_id)
        if preview is None:
            raise KeyError("Preview not found or expired")
        if time.monotonic() - float(preview["created_at"]) > PREVIEW_TTL_SECONDS:
            _previews.pop(change_id, None)
            raise KeyError("Preview not found or expired")
        preview = dict(preview)

    path = str(preview["path"])
    content = str(preview["content"])
    with _apply_lock:
        target = _resolve_editable(path)
        current = read_file(path)
        if current["sha256"] != preview["base_sha256"]:
            with _preview_lock:
                _previews.pop(change_id, None)
            raise RuntimeError("File changed after preview; create a new preview")

        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=target.parent,
                prefix=".aegis-edit-",
                suffix=".tmp",
                delete=False,
            ) as output:
                output.write(content)
                temp_path = Path(output.name)
            os.chmod(temp_path, target.stat().st_mode)
            os.replace(temp_path, target)
        finally:
            if temp_path is not None and temp_path.exists():
                temp_path.unlink()

    with _preview_lock:
        _previews.pop(change_id, None)
    updated = read_file(path)
    return {"path": path, "sha256": updated["sha256"]}
