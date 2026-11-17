from tools.registry import tool
from tools.storage import DATA_DIR


@tool(
    name="read_file",
    kind="source",
    trust="external",
    description="Read a text file from the fake shared company files.",
    schema={
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    },
)
def read_file(name: str) -> str:
    files_dir = (DATA_DIR / "files").resolve()
    path = (files_dir / name).resolve()
    if path.parent != files_dir:
        raise ValueError("File must be inside the shared files directory")
    return path.read_text(encoding="utf-8")
