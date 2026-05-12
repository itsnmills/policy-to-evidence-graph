from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any


def load_snapshot(snapshot_dir: Path) -> Dict[str, Any]:
    latest = snapshot_dir / "latest.json"
    if not latest.exists():
        return {}
    return json.loads(latest.read_text(encoding="utf-8"))


def compare_trends(current: Dict[str, Any], previous: Dict[str, Any]) -> Dict[str, Any]:
    current_readiness = current.get("readiness", {})
    previous_readiness = previous.get("readiness", {})
    current_ready = {k for k, v in current_readiness.items() if v.get("state") == "ready"}
    previous_ready = {k for k, v in previous_readiness.items() if v.get("state") == "ready"}

    improved = sorted(list(current_ready - previous_ready))
    degraded = sorted(list(previous_ready - current_ready))

    return {
        "improved": improved,
        "degraded": degraded,
        "added_ready_controls": improved,
        "lost_ready_controls": degraded,
    }


def write_trend(path: Path, payload: Dict[str, Any]) -> Path:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path
