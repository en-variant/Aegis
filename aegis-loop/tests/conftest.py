import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegis_loop.config import VICTIM_ROOT

if str(VICTIM_ROOT) not in sys.path:
    sys.path.insert(0, str(VICTIM_ROOT))
