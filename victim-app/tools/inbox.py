from tools.registry import tool
from tools.storage import DATA_DIR, load_json


@tool(
    name="read_inbox",
    kind="source",
    trust="external",
    description="Read the fake company inbox, including messages from outside senders.",
    schema={"type": "object", "properties": {}, "required": []},
)
def read_inbox() -> str:
    return str(load_json(DATA_DIR / "inbox.json"))
