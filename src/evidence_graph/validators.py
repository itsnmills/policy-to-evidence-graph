from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List
import re

CRITICALITY = {"critical", "high", "medium", "low"}
POLICY_STATUS = {"active", "draft", "retired"}
RISK_STATUS = {"open", "in_progress", "closed"}
RISK_SEVERITY = {"critical", "high", "medium", "low"}
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_MRN_HINTS = (
    r"\b(ssn|social security|mrn|medical record|patient id|mrn)\b",
    r"\bdate of birth\b",
    r"\bbirth date\b",
)
_DONT_STORE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]\d{4}\b")
_CCN_RE = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b")
_SECRET_PATTERNS = (
    re.compile(r"\b(?:AKIA|ASIA|A3T|AROA|AIDA|ANPA|AIP|ACCA)[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{36,}\b", re.IGNORECASE),
    re.compile(r"\bsk-[A-Za-z0-9]{40,}\b", re.IGNORECASE),
    re.compile(r"\b-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(api[_-]?key|secret[_-]?key|client[_-]?secret)\b", re.IGNORECASE),
)
_PHI_HEADERS = {
    "mrn",
    "patient_id",
    "patient id",
    "date_of_birth",
    "birth_date",
    "ssn",
    "dob",
    "phone",
    "medications",
    "diagnosis",
}


def _present(value: str) -> bool:
    return bool(value and str(value).strip())


def _date(value: str) -> bool:
    try:
        datetime.strptime(value, "%Y-%m-%d")
        return True
    except Exception:
        return False


def validate_records(records: Iterable[Dict[str, Any]], schema_name: str) -> List[str]:
    errors: List[str] = []
    for idx, row in enumerate(records, start=1):
        if schema_name == "control":
            if not _present(row.get("id")):
                errors.append(f"control row #{idx} missing id")
            if row.get("criticality") not in CRITICALITY:
                errors.append(f"control row #{idx} criticality invalid")
        elif schema_name == "policy":
            if not _present(row.get("policy_id")):
                errors.append(f"policy row #{idx} missing policy_id")
            if row.get("status") not in POLICY_STATUS:
                errors.append(f"policy row #{idx} status invalid")
            if row.get("updated_at") and not _date(row.get("updated_at", "")):
                errors.append(f"policy row #{idx} updated_at invalid date")
        elif schema_name == "evidence":
            for key in ("evidence_id", "title", "evidence_type", "owner", "collected_at"):
                if not _present(row.get(key)):
                    errors.append(f"evidence row #{idx} missing {key}")
            if row.get("collected_at") and not _date(row.get("collected_at", "")):
                errors.append(f"evidence row #{idx} collected_at invalid date")
            exp = row.get("expiry_days")
            if exp is not None:
                try:
                    int(exp)
                except Exception:
                    errors.append(f"evidence row #{idx} expiry_days invalid")
        elif schema_name == "system":
            for key in ("system_id", "name", "category", "owner"):
                if not _present(row.get(key)):
                    errors.append(f"system row #{idx} missing {key}")
        elif schema_name == "vendor":
            for key in ("vendor_id", "name", "status", "review_date"):
                if not _present(row.get(key)):
                    errors.append(f"vendor row #{idx} missing {key}")
            if row.get("review_date") and not _date(row.get("review_date", "")):
                errors.append(f"vendor row #{idx} review_date invalid date")
        elif schema_name == "risk":
            for key in ("risk_id", "title", "owner"):
                if not _present(row.get(key)):
                    errors.append(f"risk row #{idx} missing {key}")
            if row.get("status") not in RISK_STATUS:
                errors.append(f"risk row #{idx} invalid status")
            if row.get("severity") not in RISK_SEVERITY:
                errors.append(f"risk row #{idx} invalid severity")
            if row.get("updated_at") and not _date(row.get("updated_at", "")):
                errors.append(f"risk row #{idx} updated_at invalid date")
    return errors


def detect_phi_like_fields(path) -> List[str]:
    if isinstance(path, str):
        path = Path(path)
    if not path.exists():
        return []

    text = path.read_text(encoding="utf-8", errors="ignore")
    findings = []
    if path.suffix.lower() == ".csv":
        first_line = text.splitlines()[:1]
        if first_line:
            header = {h.strip().lower().replace("_", " ") for h in first_line[0].split(",")}
            flagged = sorted([item for item in _PHI_HEADERS if item in header or item.replace(" ", "_") in header])
            if flagged:
                findings.append(f"Potential sensitive field names in {path}: {', '.join(flagged)}")

    if _EMAIL_RE.search(text):
        findings.append(f"Potential email token in {path}")
    if _SSN_RE.search(text):
        findings.append(f"Potential SSN pattern in {path}")
    lowered = text.lower()
    if any(re.search(pattern, lowered) for pattern in _MRN_HINTS):
        findings.append(f"Potential sensitive phrase in {path}")
    if _DONT_STORE_RE.search(text):
        findings.append(f"Potential phone pattern in {path}")
    if _CCN_RE.search(text.replace(" ", "")):
        findings.append(f"Potential card data in {path}")
    for secret_pattern in _SECRET_PATTERNS:
        if secret_pattern.search(text):
            findings.append(f"Potential secret/token pattern in {path}")
            break
    return findings
