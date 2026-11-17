from tools.registry import tool
from tools.storage import DATA_DIR


@tool(
    name="send_email",
    kind="sink",
    channel="outbound",
    description="Append an email to the local fake outbox; no real email is sent.",
    schema={
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "subject": {"type": "string"},
            "body": {"type": "string"},
        },
        "required": ["to", "subject", "body"],
    },
)
def send_email(to: str, subject: str, body: str) -> str:
    with (DATA_DIR / "outbox.log").open("a", encoding="utf-8") as outbox:
        outbox.write(f"TO={to} SUBJECT={subject} BODY={body}\n")
    return "email queued in the fake outbox"
