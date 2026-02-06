from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
import yaml


def load_yaml(path: str | Path) -> Dict[str, Any]:
    path = Path(path)
    return yaml.safe_load(path.read_text()) if path.exists() else {}
