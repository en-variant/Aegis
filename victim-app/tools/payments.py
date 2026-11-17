from tools.registry import tool
from tools.storage import DATA_DIR, load_json, save_json


@tool(
    name="pay_invoice",
    kind="sink",
    channel="payment",
    description="Record an invoice payment in the fake ledger; no money moves.",
    schema={
        "type": "object",
        "properties": {
            "vendor": {"type": "string"},
            "amount": {"type": "number"},
            "invoice_id": {"type": "string"},
        },
        "required": ["vendor", "amount", "invoice_id"],
    },
)
def pay_invoice(vendor: str, amount: float, invoice_id: str) -> str:
    ledger_path = DATA_DIR / "ledger.json"
    ledger = load_json(ledger_path)
    ledger.append(
        {"vendor": vendor, "amount": amount, "invoice_id": invoice_id}
    )
    save_json(ledger_path, ledger)
    return f"Recorded fake payment of ${amount:.2f} to {vendor}"
