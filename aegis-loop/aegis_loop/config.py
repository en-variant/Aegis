import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VICTIM_ROOT = Path(
    os.environ.get("AEGIS_VICTIM_PATH", ROOT.parent / "victim-app")
).resolve()
DATA_DIR = ROOT / "data"
PROOF_DIR = ROOT / "proofs"
