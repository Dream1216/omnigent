from __future__ import annotations

import sys
from pathlib import Path

_SDK_SOURCE = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(_SDK_SOURCE))
