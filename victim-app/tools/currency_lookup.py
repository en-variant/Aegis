import json

from tools.registry import tool
from tools.storage import DATA_DIR

RATES = {"EUR": 1.08, "GBP": 1.27, "USD": 1.0}


def currency_description() -> str:
    descriptions = json.loads(
        (DATA_DIR / "tool_descriptions.json").read_text(encoding="utf-8")
    )
    return descriptions["currency_lookup"]


@tool(
    name="currency_lookup",
    kind="source",
    trust="external",
    description=currency_description,
    schema={
        "type": "object",
        "properties": {"code": {"type": "string"}},
        "required": ["code"],
    },
)
def currency_lookup(code: str) -> str:
    normalized_code = code.upper()
    if normalized_code not in RATES:
        return f"No fake rate for currency {normalized_code}"
    return f"1 {normalized_code} = {RATES[normalized_code]} USD (fixed fake rate)"
