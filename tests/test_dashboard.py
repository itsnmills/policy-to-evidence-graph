from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from evidence_graph.dashboard import write_dashboard  # noqa: E402


def _extract_payload_from_html(html_path: Path) -> str:
    html = html_path.read_text(encoding="utf-8")
    marker = '<script id="ptg-data" type="application/json">'
    start = html.index(marker) + len(marker)
    end = html.index("</script>", start)
    return html[start:end].strip()


def test_dashboard_escapes_html_breakout_sequences(tmp_path):
    payload = {
        "project": "Demo Clinic",
        "generated_at": "2026-05-12T00:00:00Z",
        "state_counts": {"ready": 3, "missing": 1},
        "matrix_rows": [],
        "gaps": [
            {
                "control_id": "SPB-1",
                "state": "missing",
                "owner": "</script><script>alert('owned')</script>",
            }
        ],
        "trend": {"week_1": "ok"},
        "integrity_manifest": {"generated_at": "2026-05-12T00:00:00Z"},
        "input_sources": [],
    }
    out = tmp_path / "dashboard"
    write_dashboard(out, payload)

    payload_text = _extract_payload_from_html(out / "index.html")
    assert "</script>" not in payload_text
    assert "\\u003c/script" in payload_text
    decoded = json.loads(payload_text)
    assert decoded["gaps"][0]["owner"] == "</script><script>alert('owned')</script>"


def test_dashboard_files_are_private(tmp_path):
    out = tmp_path / "dashboard"
    write_dashboard(
        out,
        {
            "project": "Demo Clinic",
            "generated_at": "2026-05-12T00:00:00Z",
            "state_counts": {},
            "matrix_rows": [],
            "gaps": [],
            "trend": {},
            "integrity_manifest": {},
            "input_sources": [],
        },
    )

    assert oct((out / "dashboard_data.json").stat().st_mode & 0o777) == "0o600"
    assert oct((out / "index.html").stat().st_mode & 0o777) == "0o600"
