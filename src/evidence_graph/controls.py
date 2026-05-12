from __future__ import annotations

import datetime as dt
from typing import Optional


def _days_since(value: str) -> Optional[int]:
    if not value:
        return None
    try:
        when = dt.datetime.strptime(value, "%Y-%m-%d").date()
        return (dt.date.today() - when).days
    except Exception:
        return None


def readiness_from_evidence(control_record, evidence_ids, evidence_records, stale_days_default: int):
    required = set(control_record.required_evidence_types)
    linked = [evidence_records[eid] for eid in evidence_ids if eid in evidence_records]
    present = {item.evidence_type for item in linked}
    missing = sorted(required - present)

    stale_days = []
    for item in linked:
        age = _days_since(item.collected_at)
        if age is None:
            continue
        effective = item.expiry_days or stale_days_default
        if age > effective:
            stale_days.append(item.evidence_type)

    stale_window = max(stale_days_default, int(control_record.stale_days or 180))
    due_in_days = None

    state = "unknown"
    score = 0
    reason = ""

    if not linked:
        state = "missing"
        score = 0
        reason = "No mapped evidence"
    elif missing:
        state = "partial"
        score = 55 if control_record.criticality in {"critical", "high"} else 70
        reason = "Missing required evidence type(s)"
    elif stale_days:
        state = "stale"
        score = 65
        reason = "Evidence is stale for this control"
    else:
        state = "ready"
        score = 95
        reason = "All required evidence present"

    owners = [e.owner for e in linked if e.owner]
    owner = owners[0] if owners else "Needs assignment"

    if due_in_days is None and linked:
        ages = [age for age in (_days_since(e.collected_at) for e in linked) if age is not None and age >= 0]
        if not ages:
            newest = 0
        else:
            newest = min(ages)
        due_in_days = max(stale_window - newest, 0)

    return {
        "control_id": control_record.control_id,
        "state": state,
        "evidence_count": len(linked),
        "readiness_score": score,
        "missing_evidence_types": missing,
        "stale_evidence_types": sorted(set(stale_days)),
        "reason": reason,
        "owner": owner,
        "due_in_days": due_in_days,
    }
