from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Any

import shutil
from . import normalize
from .models import (
    ProjectConfig,
    ControlRecord,
    PolicyRecord,
    ProcedureRecord,
    EvidenceRecord,
    SystemRecord,
    VendorRecord,
    RiskRecord,
)
import datetime as dt
import json
import hashlib
from .security import hash_file


def _resolve_data_path(data_dir: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    direct = data_dir / path
    if direct.exists():
        return direct
    return data_dir / path.name


def _manifest_entry(path: Path, records: int, source_type: str, project_dir: Path) -> Dict[str, object]:
    try:
        relative_path = str(path.relative_to(project_dir))
    except Exception:
        relative_path = str(path)
    try:
        stat = path.stat()
        return {
            "source_type": source_type,
            "relative_path": relative_path,
            "exists": path.exists(),
            "records": int(records),
            "bytes": int(stat.st_size),
            "modified_utc": dt.datetime.fromtimestamp(stat.st_mtime, tz=dt.timezone.utc).isoformat(),
            "sha256": hash_file(path),
        }
    except Exception:
        return {
            "source_type": source_type,
            "relative_path": str(path),
            "exists": False,
            "records": int(records),
            "bytes": 0,
            "modified_utc": "",
            "sha256": "",
        }


def load_project_config(project_dir: Path) -> ProjectConfig:
    config_file = project_dir / ".evidence_graph" / "project.yaml"
    if not config_file.exists():
        return ProjectConfig(project_name=project_dir.name)

    payload = normalize.load_yaml(config_file)
    security = payload.get("security", {})
    paths = payload.get("paths", {})
    stale = payload.get("stale_by_criticality", {})
    return ProjectConfig(
        project_name=str(payload.get("project", {}).get("name", project_dir.name)),
        owner=str(payload.get("project", {}).get("owner", "Practice Owner")),
        control_library=str(paths.get("control_library", "data/control_library.yaml")),
        policy_register=str(paths.get("policy_register", "data/policy_register.csv")),
        policy_procedure_map=str(paths.get("policy_procedure_map", "data/policy_procedure_map.yaml")),
        evidence_log=str(paths.get("evidence_log", "data/evidence_reference_log.csv")),
        system_inventory=str(paths.get("system_inventory", "data/system_inventory.csv")),
        vendor_register=str(paths.get("vendor_register", "data/vendor_register.csv")),
        risk_register=str(paths.get("risk_register", "data/risk_register.csv")),
        security_encrypt_outputs=bool(security.get("encrypt_outputs", False)),
        security_delete_plaintext=bool(security.get("delete_plaintext", False)),
        security_passphrase_env=str(security.get("passphrase_env", "PTEG_ENCRYPTION_KEY")).strip() or "PTEG_ENCRYPTION_KEY",
        security_passphrase_file=str(security.get("passphrase_file", "")).strip(),
        security_strict_mode=bool(security.get("strict_mode", False)),
        security_require_no_phi=bool(security.get("require_no_phi", True)),
        stale_by_criticality={
            "critical": int(stale.get("critical", 60)),
            "high": int(stale.get("high", 90)),
            "medium": int(stale.get("medium", 180)),
            "low": int(stale.get("low", 365)),
        },
    )


def copy_templates(project_dir: Path, template_root: Path) -> None:
    data_dir = project_dir / ".evidence_graph" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    for file in template_root.glob("*.yaml"):
        if file.name == "review_snapshot.yaml":
            continue
        shutil.copy2(file, data_dir / file.name)
    for file in template_root.glob("*.csv"):
        shutil.copy2(file, data_dir / file.name)


def load_control_library(path: Path) -> List[ControlRecord]:
    payload = normalize.load_yaml(path)
    normalized = normalize.normalize_control_library(payload)
    out: List[ControlRecord] = []
    for row in normalized:
        if not row.get("id"):
            continue
        out.append(
            ControlRecord(
                control_id=row["id"],
                title=row["title"],
                description=row["description"],
                frameworks=row["frameworks"],
                criticality=row["criticality"],
                stale_days=row["stale_days"],
                required_evidence_types=row["required_evidence_types"],
            )
        )
    return out


def load_policies(path: Path) -> List[PolicyRecord]:
    raw = normalize.normalize_policy_rows(normalize.load_csv(path))
    return [
        PolicyRecord(
            policy_id=row["policy_id"],
            title=row["title"],
            owner=row["owner"],
            status=row["status"],
            updated_at=row["updated_at"],
            description=row["description"],
            control_ids=row["control_ids"],
        )
        for row in raw
        if row.get("policy_id")
    ]


def load_procedures(path: Path) -> List[ProcedureRecord]:
    payload = normalize.load_yaml(path)
    raw = normalize.normalize_procedure_map(payload)
    return [
        ProcedureRecord(
            procedure_id=row["procedure_id"],
            title=row["title"],
            policy_ids=row["policy_ids"],
            control_ids=row["control_ids"],
        )
        for row in raw
        if row.get("procedure_id")
    ]


def load_evidence(path: Path) -> List[EvidenceRecord]:
    raw = normalize.normalize_evidence_rows(normalize.load_csv(path))
    return [
        EvidenceRecord(
            evidence_id=row["evidence_id"],
            title=row["title"],
            evidence_type=row["evidence_type"],
            owner=row["owner"],
            collected_at=row["collected_at"],
            control_ids=row["control_ids"],
            systems=row["systems"],
            vendors=row["vendors"],
            risks_mitigated=row["risks_mitigated"],
            notes=row["notes"],
            expiry_days=row["expiry_days"],
        )
        for row in raw
        if row.get("evidence_id")
    ]


def load_systems(path: Path) -> List[SystemRecord]:
    raw = normalize.normalize_system_rows(normalize.load_csv(path))
    return [
        SystemRecord(
            system_id=row["system_id"],
            name=row["name"],
            category=row["category"],
            owner=row["owner"],
            touches_phi=row["touches_phi"],
            criticality=row["criticality"],
            controls=row["controls"],
        )
        for row in raw
        if row.get("system_id")
    ]


def load_vendors(path: Path) -> List[VendorRecord]:
    raw = normalize.normalize_vendor_rows(normalize.load_csv(path))
    return [
        VendorRecord(
            vendor_id=row["vendor_id"],
            name=row["name"],
            status=row["status"],
            touches_phi=row["touches_phi"],
            touches_ai=row["touches_ai"],
            review_date=row["review_date"],
            baa_status=row["baa_status"],
            controls=row["controls"],
        )
        for row in raw
        if row.get("vendor_id")
    ]


def load_risks(path: Path) -> List[RiskRecord]:
    raw = normalize.normalize_risk_rows(normalize.load_csv(path))
    return [
        RiskRecord(
            risk_id=row["risk_id"],
            title=row["title"],
            description=row["description"],
            severity=row["severity"],
            status=row["status"],
            owner=row["owner"],
            updated_at=row["updated_at"],
            control_ids=row["control_ids"],
        )
        for row in raw
        if row.get("risk_id")
    ]


def load_graph_inputs(project_dir: Path, control_libraries: List[Path]) -> Dict[str, object]:
    cfg = load_project_config(project_dir)
    data_dir = project_dir / ".evidence_graph" / "data"

    controls = []
    input_manifest = []
    loaded_control_libraries: list[tuple[Path, int]] = []
    for control_library in control_libraries:
        if control_library.exists():
            control_rows = load_control_library(control_library)
            controls.extend(control_rows)
            loaded_control_libraries.append((control_library, len(control_rows)))
            input_manifest.append(_manifest_entry(control_library, len(control_rows), "control_library", project_dir))

    if not controls and (data_dir / cfg.control_library).exists():
        path = data_dir / cfg.control_library
        control_rows = load_control_library(path)
        controls = control_rows
        loaded_control_libraries.append((path, len(control_rows)))
        input_manifest.append(_manifest_entry(path, len(control_rows), "control_library", project_dir))

    policy_path = _resolve_data_path(data_dir, cfg.policy_register)
    policy_rows = load_policies(policy_path)
    input_manifest.append(_manifest_entry(policy_path, len(policy_rows), "policy_register", project_dir))
    procedure_path = _resolve_data_path(data_dir, cfg.policy_procedure_map)
    procedure_rows = load_procedures(procedure_path)
    input_manifest.append(_manifest_entry(procedure_path, len(procedure_rows), "policy_procedure_map", project_dir))
    evidence_path = _resolve_data_path(data_dir, cfg.evidence_log)
    evidence_rows = load_evidence(evidence_path)
    input_manifest.append(_manifest_entry(evidence_path, len(evidence_rows), "evidence_log", project_dir))
    system_path = _resolve_data_path(data_dir, cfg.system_inventory)
    system_rows = load_systems(system_path)
    input_manifest.append(_manifest_entry(system_path, len(system_rows), "system_inventory", project_dir))
    vendor_path = _resolve_data_path(data_dir, cfg.vendor_register)
    vendor_rows = load_vendors(vendor_path)
    input_manifest.append(_manifest_entry(vendor_path, len(vendor_rows), "vendor_register", project_dir))
    risk_path = _resolve_data_path(data_dir, cfg.risk_register)
    risk_rows = load_risks(risk_path)
    input_manifest.append(_manifest_entry(risk_path, len(risk_rows), "risk_register", project_dir))

    return {
        "config": cfg,
        "controls": controls,
        "policies": policy_rows,
        "procedures": procedure_rows,
        "evidence": evidence_rows,
        "systems": system_rows,
        "vendors": vendor_rows,
        "risks": risk_rows,
        "input_manifest": input_manifest,
        "source_paths": {
            "policy_register": policy_path,
            "policy_procedure_map": procedure_path,
            "evidence_log": evidence_path,
            "system_inventory": system_path,
            "vendor_register": vendor_path,
            "risk_register": risk_path,
            "control_libraries": [path for path, _ in loaded_control_libraries],
        },
    }


def store_snapshot(project_dir: Path, payload: Dict[str, Any]) -> Path:
    snap_dir = project_dir / ".evidence_graph" / "snapshots"
    snap_dir.mkdir(parents=True, exist_ok=True)
    name = payload.get("snapshot_id") or f"SNAP-{dt.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}"
    integrity_payload = dict(payload)
    integrity_payload.pop("integrity", None)
    payload_signature = hashlib.sha256(
        json.dumps(integrity_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    latest = snap_dir / "latest.json"
    previous_signature = None
    if latest.exists():
        try:
            previous_payload = json.loads(latest.read_text(encoding="utf-8"))
            previous_signature = (
                previous_payload.get("integrity", {}).get("snapshot_signature")
                if isinstance(previous_payload, dict)
                else None
            )
        except Exception:
            previous_signature = None
    chain_seed = f"{previous_signature or ''}:{payload_signature}"
    chain_signature = hashlib.sha256(chain_seed.encode("utf-8")).hexdigest()

    integrity_payload["integrity"] = {
        "snapshot_signature": payload_signature,
        "snapshot_chain_signature": chain_signature,
        "previous_snapshot_signature": previous_signature,
        "payload_digest": payload_signature,
    }
    path = snap_dir / f"{name}.json"
    path.write_text(json.dumps(integrity_payload, indent=2), encoding="utf-8")
    latest.write_text(json.dumps(integrity_payload, indent=2), encoding="utf-8")
    return path
