from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import List, Dict


def write_matrix_csv(path: Path, rows: List[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "control_id",
                "title",
                "frameworks",
                "criticality",
                "state",
                "readiness_score",
                "evidence_count",
                "missing_evidence_types",
                "stale_evidence_types",
                "owner",
                "reason",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_gaps_csv(path: Path, rows: List[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["control_id", "state", "severity", "missing_evidence_types", "owner", "due_in_days"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_input_manifest_csv(path: Path, rows: List[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "source_type",
                "relative_path",
                "records",
                "bytes",
                "modified_utc",
                "sha256",
                "exists",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "source_type": row.get("source_type", ""),
                    "relative_path": row.get("relative_path", ""),
                    "records": row.get("records", ""),
                    "bytes": row.get("bytes", ""),
                    "modified_utc": row.get("modified_utc", ""),
                    "sha256": row.get("sha256", ""),
                    "exists": row.get("exists", False),
                }
            )


def write_action_plan_csv(path: Path, gaps: List[dict], matrix_rows: List[dict]) -> None:
    rows = _prioritized_action_rows(gaps, matrix_rows)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "rank",
                "control_id",
                "state",
                "severity",
                "owner",
                "due_in_days",
                "missing_evidence_types",
                "next_action",
            ],
        )
        writer.writeheader()
        for idx, row in enumerate(rows, start=1):
            output = dict(row)
            output["rank"] = str(idx)
            writer.writerow(output)


def _severity_weight(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return order.get(str(severity).strip().lower(), 4)


def _next_action(state: str, missing: str) -> str:
    if state == "missing":
        return "Collect evidence now for required evidence type(s)."
    if state == "stale":
        return "Recollect evidence and update expiry dates."
    if state == "partial":
        return "Add remaining evidence types and refresh controls."
    return "Validate ownership and evidence quality."


def _prioritized_action_rows(gaps: List[dict], matrix_rows: List[dict]) -> List[dict]:
    actions = []
    by_control = {row["control_id"]: row for row in matrix_rows}
    for row in gaps:
        due = row.get("due_in_days")
        missing = row.get("missing_evidence_types", "")
        owner = row.get("owner", "Needs assignment")
        state = row.get("state", "unknown")
        control = by_control.get(row["control_id"], {})
        actions.append(
            {
                "control_id": row["control_id"],
                "state": state,
                "severity": row.get("severity", control.get("criticality", "medium")),
                "owner": owner,
                "due_in_days": due,
                "missing_evidence_types": missing,
                "next_action": _next_action(state, missing),
            }
        )
    actions.sort(
        key=lambda row: (
            _severity_weight(row.get("severity", "medium")),
            int(row.get("due_in_days") or 9999),
            row["control_id"],
        )
    )
    return actions


def write_summary(
    path: Path,
    readiness: Dict[str, dict],
    gaps: List[dict],
    matrix_rows: List[dict],
    trends: Dict[str, object],
    project_name: str,
    input_manifest: List[Dict] | None = None,
) -> None:
    lines = [f"# {project_name} Evidence Review Packet", ""]

    state_counts = {}
    for row in readiness.values():
        state_counts[row["state"]] = state_counts.get(row["state"], 0) + 1

    lines.append("## Readiness")
    for key in sorted(state_counts):
        lines.append(f"- {key}: {state_counts[key]}")

    lines.extend(["", "## Priority gaps"]) 
    for row in gaps[:20]:
        lines.append(
            f"- {row['control_id']} ({row['state']}, {row['severity']}) owner={row['owner']} due_in_days={row['due_in_days']}"
        )

    lines.append("")
    lines.append("## Owner action plan")
    for idx, action in enumerate(_prioritized_action_rows(gaps, matrix_rows)[:10], start=1):
        due = action.get("due_in_days")
        due_text = str(due) if due is not None else "n/a"
        lines.append(
            f"{idx}. {action['control_id']}: {action['next_action']} (owner {action['owner']}, due {due_text} days)"
        )

    lines.extend(["", "## Inputs used"])
    if input_manifest:
        for item in input_manifest:
            exists = bool(item.get("exists", False))
            state = "present" if exists else "missing"
            rel_path = str(item.get("relative_path", ""))
            rows = str(item.get("records", ""))
            lines.append(f"- {state}: {item.get('source_type')}: {rel_path} ({rows} rows)")
    else:
        lines.append("- No input manifest recorded.")

    lines.extend([
        "",
        "## Trends",
        f"- improved: {', '.join(trends.get('improved', [])) or 'none'}",
        f"- degraded: {', '.join(trends.get('degraded', [])) or 'none'}",
    ])

    path.write_text("\n".join(lines), encoding="utf-8")


def write_readiness_json(path: Path, payload: Dict) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_review_packet_html(path: Path, markdown_body: str) -> None:
    safe = (
        markdown_body.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    body = safe.replace("\n", "<br/>")
    html = f"""<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <title>Evidence Review Packet</title>
  <style>
    body {{ font-family: Inter, Arial, sans-serif; padding: 1.2rem; background:#f8fafc; color:#0f172a; }}
    .container {{ max-width: 980px; margin: 0 auto; border: 1px solid #cbd5e1; border-radius: 12px; padding: 1rem; background: #fff; }}
    h1 {{ margin-top: 0; }}
    .card {{ background:#0f172a; color:#f8fafc; padding: 1rem; border-radius: 10px; }}
  </style>
</head>
<body>
  <div class=\"container\">
    <h1>Practice Evidence Review Packet</h1>
    <div class=\"card\">{body}</div>
  </div>
</body>
</html>
"""
    path.write_text(html, encoding="utf-8")
