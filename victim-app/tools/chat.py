from tools.registry import tool
from tools.storage import DATA_DIR


@tool(
    name="post_chat",
    kind="sink",
    channel="team_chat",
    description="Append a message to the local fake team chat; nothing is sent externally.",
    schema={
        "type": "object",
        "properties": {
            "channel": {"type": "string"},
            "text": {"type": "string"},
        },
        "required": ["channel", "text"],
    },
)
def post_chat(channel: str, text: str) -> str:
    with (DATA_DIR / "chat.log").open("a", encoding="utf-8") as chat_log:
        chat_log.write(f"CHANNEL={channel} TEXT={text}\n")
    return "message posted to the fake chat"
