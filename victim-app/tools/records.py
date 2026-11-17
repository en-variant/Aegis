from tools.registry import tool
from tools.storage import DATA_DIR, load_json


@tool(
    name="get_record",
    kind="source",
    sensitivity="sensitive",
    description="Read a fake employee or admin record by record ID.",
    schema={
        "type": "object",
        "properties": {"record_id": {"type": "string"}},
        "required": ["record_id"],
    },
)
def get_record(record_id: str) -> str:
    records = load_json(DATA_DIR / "secrets.json")
    if record_id not in records:
        return f"No record found for {record_id}"
    return str(records[record_id])
