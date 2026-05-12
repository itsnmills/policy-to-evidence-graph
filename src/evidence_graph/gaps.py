from __future__ import annotations


def classify_gaps(readiness_rows, controls):
    out = []
    for item in readiness_rows:
        control = controls[item["control_id"]]
        if item["state"] in {"ready", "not_applicable"}:
            continue

        if item["state"] == "missing":
            severity = control.criticality
            default_due = 7 if control.criticality in {"critical", "high"} else 14
        elif item["state"] == "stale":
            severity = "medium" if control.criticality == "low" else "high"
            default_due = 10
        else:
            severity = "medium"
            default_due = 21

        out.append(
            {
                "control_id": item["control_id"],
                "state": item["state"],
                "severity": severity,
                "missing_evidence_types": ",".join(item["missing_evidence_types"]),
                "owner": item["owner"] or "Needs assignment",
                "due_in_days": item.get("due_in_days") if item.get("due_in_days") is not None else default_due,
            }
        )

    out = sorted(out, key=lambda r: ("critical" not in r["severity"], r["severity"], r["control_id"]))
    return out
