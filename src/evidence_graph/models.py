from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ProjectConfig:
    project_name: str
    owner: str = "Practice Owner"
    control_library: str = "data/control_library.yaml"
    policy_register: str = "data/policy_register.csv"
    policy_procedure_map: str = "data/policy_procedure_map.yaml"
    evidence_log: str = "data/evidence_reference_log.csv"
    system_inventory: str = "data/system_inventory.csv"
    vendor_register: str = "data/vendor_register.csv"
    risk_register: str = "data/risk_register.csv"
    security_encrypt_outputs: bool = False
    security_delete_plaintext: bool = False
    security_passphrase_env: str = "PTEG_ENCRYPTION_KEY"
    security_passphrase_file: str = ""
    security_strict_mode: bool = False
    security_require_no_phi: bool = True
    stale_by_criticality: Dict[str, int] = field(
        default_factory=lambda: {"critical": 60, "high": 90, "medium": 180, "low": 365}
    )


@dataclass
class ControlRecord:
    control_id: str
    title: str
    description: str = ""
    frameworks: List[str] = field(default_factory=list)
    criticality: str = "medium"
    stale_days: int = 180
    required_evidence_types: List[str] = field(default_factory=list)


@dataclass
class PolicyRecord:
    policy_id: str
    title: str
    owner: str
    status: str = "active"
    updated_at: str = ""
    description: str = ""
    control_ids: List[str] = field(default_factory=list)


@dataclass
class ProcedureRecord:
    procedure_id: str
    title: str
    policy_ids: List[str] = field(default_factory=list)
    control_ids: List[str] = field(default_factory=list)


@dataclass
class EvidenceRecord:
    evidence_id: str
    title: str
    evidence_type: str
    owner: str
    collected_at: str
    control_ids: List[str] = field(default_factory=list)
    systems: List[str] = field(default_factory=list)
    vendors: List[str] = field(default_factory=list)
    risks_mitigated: List[str] = field(default_factory=list)
    notes: str = ""
    expiry_days: Optional[int] = None


@dataclass
class SystemRecord:
    system_id: str
    name: str
    category: str
    owner: str
    touches_phi: bool = False
    criticality: str = "low"
    controls: List[str] = field(default_factory=list)


@dataclass
class VendorRecord:
    vendor_id: str
    name: str
    status: str
    touches_phi: bool = False
    touches_ai: bool = False
    review_date: str = ""
    baa_status: str = ""
    controls: List[str] = field(default_factory=list)


@dataclass
class RiskRecord:
    risk_id: str
    title: str
    description: str
    severity: str = "medium"
    status: str = "open"
    owner: str = ""
    updated_at: str = ""
    control_ids: List[str] = field(default_factory=list)
