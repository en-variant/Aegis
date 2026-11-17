import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
PRISTINE_DIR = ROOT / "pristine" / "data"


def reset_data() -> None:
    if not PRISTINE_DIR.is_dir():
        raise FileNotFoundError(f"Pristine data directory not found: {PRISTINE_DIR}")
    if DATA_DIR.exists():
        shutil.rmtree(DATA_DIR)
    shutil.copytree(PRISTINE_DIR, DATA_DIR)


if __name__ == "__main__":
    reset_data()
    print("Fake data reset to its pristine state.")
