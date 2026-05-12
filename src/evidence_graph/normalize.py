from __future__ import annotations

import csv
from typing import Any, Dict, List, Optional


def _normalize_bool(value: str) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _split_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [part.strip() for part in str(value).replace(";", ",").split(",") if part.strip()]


def _normalize_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {k: (v.strip() if isinstance(v, str) else v) for k, v in row.items()}


def load_csv(path):
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = []
        for row in reader:
            rows.append(_normalize_row(row))
    return rows


def load_yaml(path):
    try:
        import yaml

        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        import json

        with path.open("r", encoding="utf-8") as f:
            text = [line.rstrip() for line in f.readlines()]
            if not text:
                return {}

            compact = "\n".join(text).strip()
            if compact.startswith("{") and compact.endswith("}"):
                return json.loads(compact)

            # Minimal fallback parser for simple whitespace-indented YAML with nested mappings
            root = {}
            stack = [(-1, root)]
            for raw in text:
                if not raw.strip() or raw.lstrip().startswith("#"):
                    continue
                indent = len(raw) - len(raw.lstrip())
                line = raw.strip()
                if ":" not in line:
                    continue

                while stack and indent <= stack[-1][0]:
                    stack.pop()
                if not stack:
                    stack.append((-1, root))

                parent = stack[-1][1]
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()

                if value:
                    if value.lower() in ("true", "false"):
                        parent[key] = value.lower() == "true"
                    elif value.isdigit():
                        parent[key] = int(value)
                    else:
                        parent[key] = value
                else:
                    child = {}
                    parent[key] = child
                    stack.append((indent, child))

            return root


def normalize_controls(raw: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    for row in raw:
        normalized.append(
            {
                "id": str(row.get("id") or row.get("control_id") or "").strip(),
                "title": str(row.get("title") or "").strip(),
                "description": str(row.get("description") or "").strip(),
                "frameworks": _split_list(row.get("frameworks") or ""),
                "criticality": str(row.get("criticality") or "medium").strip().lower(),
                "stale_days": int(row.get("stale_days") or 0) or 180,
                "required_evidence_types": _split_list(row.get("required_evidence_types") or ""),
            }
        )
    return normalized


def normalize_policy_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for row in rows:
        row = _normalize_row(row)
        out.append(
            {
                "policy_id": str(row.get("policy_id") or "").strip(),
                "title": str(row.get("title") or "").strip(),
                "owner": str(row.get("owner") or "").strip(),
                "status": str(row.get("status") or "active").strip().lower(),
                "updated_at": str(row.get("updated_at") or "").strip(),
                "description": str(row.get("description") or "").strip(),
                "control_ids": _split_list(row.get("control_ids") or ""),
            }
        )
    return out


def normalize_evidence_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for row in rows:
        row = _normalize_row(row)
        expiry = row.get("expiry_days")
        if isinstance(expiry, str) and expiry.strip() == "":
            expiry = None
        out.append(
            {
                "evidence_id": str(row.get("evidence_id") or "").strip(),
                "title": str(row.get("title") or "").strip(),
                "evidence_type": str(row.get("evidence_type") or "").strip(),
                "owner": str(row.get("owner") or "").strip(),
                "collected_at": str(row.get("collected_at") or "").strip(),
                "control_ids": _split_list(row.get("control_ids") or ""),
                "systems": _split_list(row.get("systems") or ""),
                "vendors": _split_list(row.get("vendors") or ""),
                "risks_mitigated": _split_list(row.get("risks_mitigated") or ""),
                "notes": str(row.get("notes") or "").strip(),
                "expiry_days": int(expiry) if expiry not in (None, "") else None,
            }
        )
    return out


def normalize_system_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for row in rows:
        row = _normalize_row(row)
        out.append(
            {
                "system_id": str(row.get("system_id") or "").strip(),
                "name": str(row.get("name") or "").strip(),
                "category": str(row.get("category") or "").strip(),
                "owner": str(row.get("owner") or "").strip(),
                "touches_phi": _normalize_bool(row.get("touches_phi")),
                "criticality": str(row.get("criticality") or "low").strip().lower(),
                "controls": _split_list(row.get("controls") or ""),
            }
        )
    return out


def normalize_vendor_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for row in rows:
        row = _normalize_row(row)
        out.append(
            {
                "vendor_id": str(row.get("vendor_id") or "").strip(),
                "name": str(row.get("name") or "").strip(),
                "status": str(row.get("status") or "").strip(),
                "touches_phi": _normalize_bool(row.get("touches_phi")),
                "touches_ai": _normalize_bool(row.get("touches_ai")),
                "review_date": str(row.get("review_date") or "").strip(),
                "baa_status": str(row.get("baa_status") or "").strip(),
                "controls": _split_list(row.get("controls") or ""),
            }
        )
    return out


def normalize_risk_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for row in rows:
        row = _normalize_row(row)
        out.append(
            {
                "risk_id": str(row.get("risk_id") or "").strip(),
                "title": str(row.get("title") or "").strip(),
                "description": str(row.get("description") or "").strip(),
                "severity": str(row.get("severity") or "medium").strip().lower(),
                "status": str(row.get("status") or "open").strip().lower(),
                "owner": str(row.get("owner") or "").strip(),
                "updated_at": str(row.get("updated_at") or "").strip(),
                "control_ids": _split_list(row.get("control_ids") or ""),
            }
        )
    return out


def normalize_control_library(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw_controls = payload.get("controls", []) or []
    normalized = normalize_controls(raw_controls)
    if "name" in payload:
        name = str(payload.get("name") or "").strip()
        if name:
            for record in normalized:
                record["library"] = name
    return normalized


def normalize_procedure_map(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = payload.get("procedures", []) or []
    normalized = []
    for row in rows:
        normalized.append(
            {
                "procedure_id": str(row.get("procedure_id") or "").strip(),
                "title": str(row.get("title") or "").strip(),
                "policy_ids": _split_list(row.get("policy_ids") or ""),
                "control_ids": _split_list(row.get("control_ids") or ""),
            }
        )
    return normalized
