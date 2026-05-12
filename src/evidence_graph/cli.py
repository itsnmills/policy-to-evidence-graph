from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import secrets
import string
import shutil
import zipfile
from pathlib import Path
from typing import Dict, Iterable, Optional

from . import normalize
from .models import ProjectConfig
from .ingest import (
    copy_templates,
    load_graph_inputs,
    load_project_config,
    store_snapshot,
)
from .evidence import map_evidence_to_controls
from .controls import readiness_from_evidence
from .gaps import classify_gaps
from .trends import compare_trends, load_snapshot
from .reports import (
    write_action_plan_csv,
    write_gaps_csv,
    write_matrix_csv,
    write_readiness_json,
    write_input_manifest_csv,
    write_summary,
    write_review_packet_html,
)
from .dashboard import write_dashboard
from .validators import detect_phi_like_fields, validate_records
from .graph import build_graph
from .security import (
    EncryptionError,
    build_integrity_manifest,
    decrypt_file,
    _validate_passphrase,
    encrypt_file,
    resolve_passphrase,
    verify_file_integrity,
    verify_snapshot_chain,
    write_integrity_manifest,
)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _data_dir(project_dir: Path, cfg: ProjectConfig) -> Dict[str, Path]:
    base = project_dir / ".evidence_graph" / "data"
    return {
        "control_library": base / Path(cfg.control_library).name,
        "policy_register": base / Path(cfg.policy_register).name,
        "policy_procedure_map": base / Path(cfg.policy_procedure_map).name,
        "evidence_log": base / Path(cfg.evidence_log).name,
        "system_inventory": base / Path(cfg.system_inventory).name,
        "vendor_register": base / Path(cfg.vendor_register).name,
        "risk_register": base / Path(cfg.risk_register).name,
    }


def _control_libraries(project_dir: Path) -> list[Path]:
    local = project_dir / "control_libraries"
    repo_default = _project_root() / "control_libraries"
    if local.exists():
        return sorted(local.glob("*.yaml"))
    if repo_default.exists():
        return sorted(repo_default.glob("*.yaml"))
    return []


def _project_audit_log(project_dir: Path) -> Path:
    return project_dir / ".evidence_graph" / "operations.log"


def _append_audit_entry(project_dir: Path, event: str, details: Dict[str, object]) -> None:
    entry = {
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "event": event,
        "details": details,
    }
    log_path = _project_audit_log(project_dir)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
    _set_private_permissions(log_path)


def _artifact_label(project_dir: Path, path: Path) -> str:
    try:
        return str(path.relative_to(project_dir / "out"))
    except Exception:
        pass
    try:
        return str(path.relative_to(project_dir))
    except Exception:
        return str(path)


def _format_audit_path(path: Path | None) -> str:
    return str(path) if path else "n/a"


def _set_private_permissions(path: Path, is_dir: bool = False) -> None:
    if not path.exists():
        return
    try:
        path.chmod(0o700 if is_dir else 0o600)
    except Exception:
        pass


def _mode_is_private(path: Path) -> tuple[bool, int]:
    try:
        mode = path.stat().st_mode & 0o777
        return (mode & 0o077) == 0, mode
    except Exception:
        return False, 0


def _permission_status(path: Path) -> dict[str, object]:
    if not path.exists():
        return {"exists": False}
    private, mode = _mode_is_private(path)
    return {
        "exists": True,
        "is_dir": path.is_dir(),
        "mode_octal": f"{mode:04o}",
        "private": private,
    }


def _timestamp_age_days(timestamp: str | None) -> Optional[int]:
    if not timestamp:
        return None
    try:
        parsed = dt.datetime.fromisoformat(timestamp)
    except Exception:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return max(0, int((dt.datetime.now(dt.timezone.utc) - parsed).total_seconds() / 86400))


def _write_security_audit_reports(out_dir: Path, audit: dict) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    report_json = json.dumps(audit, indent=2, sort_keys=True)
    json_path = out_dir / "security_audit_report.json"
    json_path.write_text(report_json, encoding="utf-8")
    _set_private_permissions(json_path)

    md_lines = [
        f"# {audit['project']} Security Audit Report",
        f"Generated: {audit['generated_at']}",
        "",
        f"Mode: {'strict' if audit['strict_mode'] else 'standard'}",
        f"Encryption checks enabled: {'yes' if audit['check_encrypt'] else 'no'}",
        "",
        "## Findings",
        f"- Issues: {len(audit['issues'])}",
        f"- Warnings: {len(audit['warnings'])}",
        "",
        "## Check details",
    ]

    for name, payload in audit["checks"].items():
        md_lines.extend(
            [
                f"### {name}",
                "```json",
                json.dumps(payload, indent=2, sort_keys=True),
                "```",
                "",
            ]
        )

    if audit["issues"]:
        md_lines.extend(["## Blocking issues"] + [f"- {item}" for item in audit["issues"]] + [""])
    if audit["warnings"]:
        md_lines.extend(["## Warnings"] + [f"- {item}" for item in audit["warnings"]] + [""])

    if not audit["issues"] and not audit["warnings"]:
        md_lines.extend(["## Result", "No security posture issues detected with current configuration and artifacts.", ""])

    md_lines.extend(
        [
            "## Recommended clinic workflow",
            "- Keep `.evidence_graph` and `out/` restricted to owner-only access.",
            "- Use `--encrypt --delete-plaintext` before sharing review packets.",
            "- Run `evidence-graph security-audit --strict --encrypt` before sharing packet artifacts.",
            "- Archive `out/security_audit_report.json` with packet deliverables.",
        ]
    )

    md_path = out_dir / "security_audit_report.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")
    _set_private_permissions(md_path)
    return json_path, md_path


def _require_clean_security_posture(
    project_dir: Path,
    cfg: ProjectConfig,
    args: argparse.Namespace,
    operation: str = "operation",
) -> bool:
    strict_mode = bool(getattr(args, "strict", False) or cfg.security_strict_mode)
    check_encrypt = bool(getattr(args, "encrypt", False) or cfg.security_encrypt_outputs)
    if not strict_mode:
        return True

    out = project_dir / "out"
    audit = _build_security_audit(
        project_dir,
        cfg,
        strict_mode=True,
        check_encrypt=check_encrypt,
    )
    _write_security_audit_reports(out, audit)
    if not audit["issues"]:
        print(f"Security gate passed for {operation}.")
        return True

    print(f"Security gate blocked {operation}:")
    for item in audit["issues"]:
        print(f"- {item}")
    return False


def _secure_project_paths(project_dir: Path) -> None:
    base = project_dir / ".evidence_graph"
    _set_private_permissions(base, is_dir=True)
    for child in base.rglob("*"):
        _set_private_permissions(child, is_dir=child.is_dir())

    out = project_dir / "out"
    _set_private_permissions(out, is_dir=True)
    for child in out.rglob("*"):
        _set_private_permissions(child, is_dir=child.is_dir())


def _set_mode_paths_private(paths: Iterable[Path]) -> None:
    for candidate in paths:
        if candidate.exists() and candidate.is_file():
            _set_private_permissions(candidate)


def _add_project_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project", "-p", default=".", help="Project directory")


def _add_security_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt selected outputs with local key material.",
    )
    parser.add_argument(
        "--passphrase-env",
        default=None,
        help="Environment variable containing the encryption passphrase.",
    )
    parser.add_argument(
        "--passphrase-file",
        default=None,
        help="Path to file containing the encryption passphrase (preferred over env var if set).",
    )
    parser.add_argument(
        "--delete-plaintext",
        action="store_true",
        help="Delete plaintext outputs after encrypting.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enable strict security posture checks (fail on PHI-like data findings).",
    )


def _default_passphrase_file(project_dir: Path) -> Path:
    return project_dir / ".evidence_graph" / "secrets" / "passphrase.txt"


def _generate_passphrase(length: int = 48) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _resolve_passphrase(project_dir: Path, cfg: ProjectConfig, args: argparse.Namespace) -> str | None:
    env_name = args.passphrase_env or cfg.security_passphrase_env
    passphrase_file = args.passphrase_file or cfg.security_passphrase_file
    default_file = _default_passphrase_file(project_dir)
    if not passphrase_file and default_file.exists():
        passphrase_file = str(default_file)
    if passphrase_file:
        candidate = Path(passphrase_file)
        if not candidate.is_absolute():
            passphrase_file = str((project_dir / candidate).resolve())
    try:
        passphrase = resolve_passphrase(env_name, passphrase_file)
    except Exception as exc:
        print(f"Passphrase source failed: {exc}")
        return None
    if not passphrase:
        source = passphrase_file or (f"environment variable {env_name!r}" if env_name else "configured key source")
        print(f"Missing passphrase. Configure a secure value at {source}.")
        return None
    return passphrase


def _snapshot_signature_lookup(snapshot_dir: Path, signature: str) -> Path | None:
    if not signature:
        return None
    for path in snapshot_dir.glob("*.json"):
        if path.name == "latest.json":
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            integrity = payload.get("integrity", {})
            if isinstance(integrity, dict) and integrity.get("snapshot_signature") == signature:
                return path
        except Exception:
            continue
    return None


def _encrypt_outputs(
    project_dir: Path,
    cfg: ProjectConfig,
    args: argparse.Namespace,
    operation: str,
    outputs: Dict[str, Path],
) -> int:
    if not (getattr(args, "encrypt", False) or cfg.security_encrypt_outputs):
        return 0

    passphrase = _resolve_passphrase(project_dir, cfg, args)
    if not passphrase:
        return 1

    out = project_dir / "out"
    encrypted: Dict[str, str] = {}
    manifest_inputs: Dict[str, Path] = {}
    delete_plaintext = (
        getattr(args, "delete_plaintext", False)
        or cfg.security_delete_plaintext
        or cfg.security_strict_mode
    )
    for key, source in list(outputs.items()):
        if not source.exists():
            continue
        encrypted_target = source.with_suffix(source.suffix + ".enc")
        source_label = _artifact_label(project_dir, source)
        encrypted_label = _artifact_label(project_dir, encrypted_target)
        try:
            encrypt_file(source, encrypted_target, passphrase)
        except EncryptionError as exc:
            print(f"Encryption failed for {source}: {exc}")
            return 1
        _set_private_permissions(encrypted_target)
        _set_private_permissions(source)
        encrypted[encrypted_label] = _artifact_label(project_dir, encrypted_target)
        if delete_plaintext:
            outputs.pop(key, None)
            outputs[encrypted_label] = encrypted_target
            manifest_inputs[f"{encrypted_label}"] = encrypted_target
        else:
            outputs[f"{key}.enc"] = encrypted_target
            manifest_inputs[source_label] = source
            manifest_inputs[f"{encrypted_label}"] = encrypted_target
        if delete_plaintext:
            try:
                source.unlink()
            except Exception:
                pass

    bundle = {
        "operation": operation,
        "project": cfg.project_name,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "passphrase_env": cfg.security_passphrase_env,
        "strict_mode": bool(cfg.security_strict_mode or getattr(args, "strict", False)),
        "delete_plaintext": bool(delete_plaintext),
        "encrypted_files": encrypted,
        "integrity": build_integrity_manifest(manifest_inputs),
    }
    (out / "security_bundle.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    _set_private_permissions(out / "security_bundle.json")
    print(f"Encrypted outputs available in {out} under .enc files.")
    return 0


def _write_release_package(package_name: Path | None, out: Path, out_files: Dict[str, Path]) -> Path:
    if package_name is None:
        return out / "review_packet_bundle.zip"
    target = Path(package_name).expanduser()
    if target.suffix.lower() != ".zip":
        target = target.with_suffix(".zip")
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in out_files.values():
            if not path.exists():
                continue
            try:
                arcname = f"review-packet/{path.relative_to(out.parent).as_posix()}"
            except Exception:
                arcname = f"review-packet/{path.name}"
            zf.write(path, arcname=arcname)
    return target


def _read_input_manifest_csv(out_dir: Path) -> list[dict]:
    path = out_dir / "input_manifest.csv"
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as stream:
        return [dict(row) for row in csv.DictReader(stream)]


def _build_security_audit(project_dir: Path, cfg: ProjectConfig, strict_mode: bool, check_encrypt: bool) -> dict:
    checks: dict[str, dict[str, object]] = {}
    issues: list[str] = []
    warnings: list[str] = []

    project_config = _project_audit_log(project_dir).parent / "project.yaml"
    checks["project_config"] = _permission_status(project_config)
    if not checks["project_config"]["exists"]:
        issues.append(f"Missing required project config: {project_config}")

    data_paths = _data_dir(project_dir, cfg)
    checks["required_input_files"] = {}
    for name, path in data_paths.items():
        status = _permission_status(path)
        checks["required_input_files"][name] = status
        if not status["exists"]:
            issues.append(f"Missing required input file: {path}")

    if checks["required_input_files"]:
        sensitive_fields = []
        for path in data_paths.values():
            if path.exists():
                sensitive_fields.extend(detect_phi_like_fields(path))

        if sensitive_fields:
            key = "phi_like_findings"
            checks[key] = {"count": len(sensitive_fields), "examples": sensitive_fields[:10]}
            if strict_mode:
                issues.append("PHI-like findings detected in required input files.")
            else:
                warnings.append("PHI-like findings detected in required input files.")

    project_paths = {
        "audit_log": _project_audit_log(project_dir),
        ".evidence_graph_dir": project_dir / ".evidence_graph",
        "out_dir": project_dir / "out",
    }
    checks["project_path_permissions"] = {name: _permission_status(path) for name, path in project_paths.items()}

    for name, value in checks["project_path_permissions"].items():
        if name in {"audit_log", ".evidence_graph_dir", "out_dir"}:
            if value.get("exists") and not value.get("private", True):
                if name == "audit_log":
                    issues.append(f"{name} is not owner-only: mode={value.get('mode_octal')}")
                else:
                    warnings.append(f"{name} is not owner-only: mode={value.get('mode_octal')}")

    secret_file = _default_passphrase_file(project_dir)
    checks["passphrase_file"] = _permission_status(secret_file)
    if check_encrypt:
        checks["encryption"] = {"enabled": True}
        try:
            source = cfg.security_passphrase_file or str(secret_file)
            checks["encryption"]["passphrase_env"] = cfg.security_passphrase_env or "unset"
            checks["encryption"]["source"] = str(source)
            passphrase = resolve_passphrase(cfg.security_passphrase_env, source)
            source_path = Path(source)
            if not source_path.is_absolute():
                source_path = (project_dir / source_path).resolve()
            checks["encryption"]["passphrase_file_permissions"] = _permission_status(source_path)
            if source_path.exists() and not checks["encryption"]["passphrase_file_permissions"].get("private"):
                issue_message = f"Passphrase file is not owner-only: {source_path}"
                if strict_mode:
                    issues.append(issue_message)
                else:
                    warnings.append(issue_message)
        except Exception as exc:
            passphrase = None
            checks["encryption"]["configured"] = False
            checks["encryption"]["error"] = str(exc)
        else:
            checks["encryption"]["configured"] = bool(passphrase)
            if passphrase:
                checks["encryption"]["passphrase_length"] = len(passphrase)
                try:
                    _validate_passphrase(passphrase)
                except EncryptionError as exc:
                    issues.append(f"Weak passphrase configured for encryption: {exc}")
            else:
                issues.append("Encryption requested but no valid passphrase source found.")
    else:
        checks["encryption"] = {"enabled": False}

    integrity_path = project_dir / "out" / "integrity_manifest.json"
    checks["integrity_manifest"] = _permission_status(integrity_path)
    if integrity_path.exists():
        try:
            manifest = json.loads(integrity_path.read_text(encoding="utf-8"))
            checks["integrity_manifest"]["valid"], issues_detail = verify_file_integrity(
                manifest,
                base_dir=integrity_path.parent,
            )
            if issues_detail:
                checks["integrity_manifest"]["issues"] = issues_detail
                if strict_mode:
                    issues.extend(issues_detail)
                else:
                    warnings.extend(issues_detail)
        except Exception as exc:
            checks["integrity_manifest"]["parse_error"] = str(exc)
            warnings.append(f"Could not parse integrity manifest: {exc}")
    else:
        checks["integrity_manifest"]["valid"] = False
        warnings.append("No integrity manifest found at out/integrity_manifest.json")

    latest_snapshot = project_dir / ".evidence_graph" / "snapshots" / "latest.json"
    checks["snapshot"] = _permission_status(latest_snapshot)
    if latest_snapshot.exists():
        checks["snapshot"]["status"] = "found"
        checks["snapshot"]["path"] = str(latest_snapshot)
        try:
            snapshot_payload = json.loads(latest_snapshot.read_text(encoding="utf-8"))
            snapshot_generated = snapshot_payload.get("generated_at")
            checks["snapshot"]["generated_at"] = snapshot_generated or "missing"
            age_days = _timestamp_age_days(snapshot_generated) if isinstance(snapshot_generated, str) else None
            if age_days is not None:
                checks["snapshot"]["age_days"] = age_days
                if age_days > 365 and strict_mode:
                    warnings.append("Latest snapshot is older than 365 days.")
            snapshot_issues = verify_snapshot_chain(snapshot_payload, None)
            if snapshot_issues:
                checks["snapshot"]["chain_ok"] = False
                checks["snapshot"]["issues"] = snapshot_issues
                if strict_mode:
                    issues.extend(snapshot_issues)
                else:
                    warnings.extend(snapshot_issues)
            else:
                checks["snapshot"]["chain_ok"] = True
        except Exception as exc:
            checks["snapshot"]["status"] = f"invalid: {exc}"
            warnings.append(f"Could not parse latest snapshot: {exc}")
    else:
        checks["snapshot"]["status"] = "not_found"

    audit = {
        "project": cfg.project_name,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "strict_mode": strict_mode,
        "check_encrypt": bool(check_encrypt),
        "checks": checks,
        "issues": issues,
        "warnings": warnings,
    }
    return audit


def cmd_security_audit(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).resolve()
    cfg = load_project_config(project_dir)
    strict_mode = bool(getattr(args, "strict", False) or cfg.security_strict_mode)
    check_encrypt = bool(getattr(args, "encrypt", False) or cfg.security_encrypt_outputs)

    out = project_dir / "out"
    out.mkdir(parents=True, exist_ok=True)
    audit = _build_security_audit(project_dir, cfg, strict_mode, check_encrypt)
    failed = bool(audit["issues"])
    json_path, md_path = _write_security_audit_reports(out, audit)

    if failed and strict_mode:
        print("Security audit failed:")
        for item in audit["issues"]:
            print(f"- {item}")
        _append_audit_entry(
            project_dir,
            "security_audit_failed",
            {"project": cfg.project_name, "issues": audit["issues"], "warnings": audit["warnings"]},
        )
        return 1

    print(f"Security audit written to: {json_path}")
    if audit["issues"]:
        for item in audit["issues"]:
            print(f"- {item}")
    _append_audit_entry(
        project_dir,
        "security_audit_completed",
        {"project": cfg.project_name, "issues": len(audit["issues"]), "warnings": len(audit["warnings"])},
    )
    print(f"Security audit report: {json_path}")
    print(f"Security audit markdown: {md_path}")
    return 0


def cmd_generate_passphrase(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).resolve()
    passphrase = _generate_passphrase(max(int(args.length), 32))
    if args.output:
        target = Path(args.output).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(passphrase + "\n", encoding="utf-8")
        _set_private_permissions(target)
        print(f"Passphrase written to: {target}")
        _append_audit_entry(
            project_dir,
            "passphrase_generated",
            {"project": project_dir.name, "path": str(target), "length": len(passphrase)},
        )
        return 0

    print(passphrase)
    print("Warning: this passphrase will not be stored. Save it in a secure password manager.")
    _append_audit_entry(
        project_dir,
        "passphrase_generated",
        {"project": project_dir.name, "length": len(passphrase), "stored": False},
    )
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).resolve()
    cfg_path = project_dir / ".evidence_graph" / "project.yaml"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    secrets_dir = cfg_path.parent / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    gitignore_path = secrets_dir.joinpath(".gitignore")
    if not gitignore_path.exists():
        gitignore_path.write_text("passphrase.txt\n", encoding="utf-8")

    cfg_path.write_text(
        "\n".join(
            [
                "project:",
                f"  name: {project_dir.name}",
                "  owner: Practice Owner",
                "paths:",
                "  control_library: data/control_library.yaml",
                "  policy_register: data/policy_register.csv",
                "  policy_procedure_map: data/policy_procedure_map.yaml",
                "  evidence_log: data/evidence_reference_log.csv",
                "  system_inventory: data/system_inventory.csv",
                "  vendor_register: data/vendor_register.csv",
                "  risk_register: data/risk_register.csv",
                "security:",
                "  encrypt_outputs: false",
                "  passphrase_env: PTEG_ENCRYPTION_KEY",
                "  passphrase_file: .evidence_graph/secrets/passphrase.txt",
                "  delete_plaintext: false",
                "  require_no_phi: true",
                "  strict_mode: false",
                "stale_by_criticality:",
                "  critical: 60",
                "  high: 90",
                "  medium: 180",
                "  low: 365",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    copy_templates(project_dir, _project_root() / "templates")
    root_data = project_dir / ".evidence_graph" / "data"
    root_data.mkdir(parents=True, exist_ok=True)
    default_library = _project_root() / "control_libraries" / "small_practice_security_baseline.yaml"
    if default_library.exists():
        shutil.copy2(default_library, root_data / "control_library.yaml")

    _secure_project_paths(project_dir)
    _append_audit_entry(
        project_dir,
        "project_initialized",
        {"project": project_dir.name, "passphrase_file": str(_default_passphrase_file(project_dir))},
    )
    print(f"Initialized evidence graph project at {project_dir}")
    print(f"Secure passphrase file configured at: {_default_passphrase_file(project_dir)}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).resolve()
    cfg = load_project_config(project_dir)
    paths = _data_dir(project_dir, cfg)

    missing = [p for p in paths.values() if not p.exists()]
    if missing:
        print("Missing files:")
        for path in missing:
            print(f"- {path}")
        return 1

    controls = []
    for library in _control_libraries(project_dir):
        controls.extend(normalize.normalize_controls(normalize.load_yaml(library).get("controls", [])))
    if not controls:
        controls = normalize.normalize_controls(normalize.load_yaml(paths["control_library"]).get("controls", []))

    rows = [
        *(validate_records(controls, "control")),
        *(validate_records(normalize.normalize_policy_rows(normalize.load_csv(paths["policy_register"])), "policy")),
        *(validate_records(normalize.normalize_evidence_rows(normalize.load_csv(paths["evidence_log"])), "evidence")),
        *(validate_records(normalize.normalize_system_rows(normalize.load_csv(paths["system_inventory"])), "system")),
        *(validate_records(normalize.normalize_vendor_rows(normalize.load_csv(paths["vendor_register"])), "vendor")),
        *(validate_records(normalize.normalize_risk_rows(normalize.load_csv(paths["risk_register"])), "risk")),
    ]

    phi_rows: list[str] = []
    for path in paths.values():
        phi_rows.extend(detect_phi_like_fields(path))
    strict_mode = bool(getattr(args, "strict", False) or cfg.security_strict_mode)
    require_no_phi = cfg.security_require_no_phi or strict_mode

    if rows or (strict_mode and require_no_phi and phi_rows):
        print("Validation failed:")
        for error in rows + (phi_rows if strict_mode else []):
            print(f"- {error}")
        _append_audit_entry(
            project_dir,
            "validate_failed",
            {
                "project": cfg.project_name,
                "strict_mode": strict_mode,
                "issues": rows + (phi_rows if strict_mode else []),
            },
        )
        return 1
    if phi_rows and cfg.security_require_no_phi and not strict_mode:
        print("PHI-like findings detected:")
        for warning in phi_rows:
            print(f"- {warning}")

    _secure_project_paths(project_dir)
    _append_audit_entry(project_dir, "validate_passed", {"project": cfg.project_name, "strict_mode": strict_mode})
    print("Validation complete.")
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).resolve()
    cfg = load_project_config(project_dir)
    if not _require_clean_security_posture(project_dir, cfg, args, operation="build"):
        return 1
    payload = load_graph_inputs(project_dir, _control_libraries(project_dir))
    cfg = payload["config"]
    input_manifest = payload.get("input_manifest", [])
    _append_audit_entry(project_dir, "build_started", {"project": cfg.project_name})
    out = project_dir / "out"
    out.mkdir(parents=True, exist_ok=True)

    controls = {c.control_id: c for c in payload["controls"]}
    policies = {p.policy_id: p for p in payload["policies"]}
    procedures = {p.procedure_id: p for p in payload["procedures"]}
    evidences = payload["evidence"]
    systems = {s.system_id: s for s in payload["systems"]}
    vendors = {v.vendor_id: v for v in payload["vendors"]}
    risks = {r.risk_id: r for r in payload["risks"]}

    evidence_by_id = {e.evidence_id: e for e in evidences}
    system_control_map = {sid: (sys.controls[0] if sys.controls else "") for sid, sys in systems.items()}
    vendor_control_map = {vid: (ven.controls[0] if ven.controls else "") for vid, ven in vendors.items()}

    evidence_map = map_evidence_to_controls(evidences, controls, system_control_map, vendor_control_map)

    matrix_rows = []
    readiness = {}
    for control_id, control in controls.items():
        data = readiness_from_evidence(
            control,
            evidence_map.get(control_id, []),
            evidence_by_id,
            cfg.stale_by_criticality.get(control.criticality, 180),
        )
        readiness[control_id] = data
        matrix_rows.append(
            {
                "control_id": control_id,
                "title": control.title,
                "frameworks": ",".join(control.frameworks),
                "criticality": control.criticality,
                "state": data["state"],
                "readiness_score": data["readiness_score"],
                "evidence_count": data["evidence_count"],
                "missing_evidence_types": ",".join(data["missing_evidence_types"]),
                "stale_evidence_types": ",".join(data["stale_evidence_types"]),
                "owner": data["owner"],
                "reason": data["reason"],
            }
        )

    readiness_list = [readiness[cid] for cid in sorted(readiness)]
    gap_rows = classify_gaps(readiness_list, controls)
    graph_payload = build_graph(controls, policies, procedures, systems, vendors, risks, evidence_map)
    previous = load_snapshot(project_dir / ".evidence_graph" / "snapshots")
    if args.previous_snapshot:
        previous = json.loads(Path(args.previous_snapshot).read_text(encoding="utf-8"))

    trend_payload = compare_trends({"readiness": readiness}, previous)

    (out / "evidence_graph.json").write_text(
        json.dumps(
            {
                "nodes": graph_payload.nodes,
                "edges": [
                    {"source_type": source_type, "source_id": source_id, "type": edge_type, "target_id": target_id}
                    for (source_type, source_id, edge_type, target_id) in graph_payload.edges
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    write_matrix_csv(out / "control_to_evidence_matrix.csv", matrix_rows)
    write_gaps_csv(out / "missing_evidence_gaps.csv", gap_rows)
    write_action_plan_csv(out / "priority_action_plan.csv", gap_rows, matrix_rows)
    write_input_manifest_csv(out / "input_manifest.csv", input_manifest)

    summary = {
        "project": cfg.project_name,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "owner": cfg.owner,
        "readiness": readiness,
        "policy_count": len(policies),
        "risk_count": len(risks),
        "vendor_count": len(vendors),
        "system_count": len(systems),
        "source_count": len(input_manifest),
    }
    write_readiness_json(out / "readiness_summary.json", summary)
    write_summary(
        out / "review_packet.md",
        readiness,
        gap_rows,
        matrix_rows,
        trend_payload,
        cfg.project_name,
        input_manifest=input_manifest,
    )
    review_packet_html = out / "review_packet.html"
    write_review_packet_html(review_packet_html, (out / "review_packet.md").read_text(encoding="utf-8"))
    (out / "review_packet.json").write_text(
        json.dumps({"summary": summary, "gaps": gap_rows, "trend": trend_payload}, indent=2),
        encoding="utf-8",
    )

    output_files = {
        "control_to_evidence_matrix.csv": out / "control_to_evidence_matrix.csv",
        "missing_evidence_gaps.csv": out / "missing_evidence_gaps.csv",
        "priority_action_plan.csv": out / "priority_action_plan.csv",
        "input_manifest.csv": out / "input_manifest.csv",
        "readiness_summary.json": out / "readiness_summary.json",
        "review_packet.md": out / "review_packet.md",
        "review_packet.json": out / "review_packet.json",
        "review_packet.html": review_packet_html,
        "evidence_graph.json": out / "evidence_graph.json",
        "dashboard/dashboard_data.json": out / "dashboard" / "dashboard_data.json",
    }

    state_counts = {}
    for row in matrix_rows:
        state_counts[row["state"]] = state_counts.get(row["state"], 0) + 1
    write_dashboard(
        out / "dashboard",
        {
            "project": cfg.project_name,
            "generated_at": summary["generated_at"],
            "state_counts": state_counts,
            "matrix_rows": matrix_rows,
            "gaps": gap_rows,
            "trend": trend_payload,
            "integrity_manifest": {},
            "input_sources": input_manifest,
        },
    )

    encryption_result = _encrypt_outputs(project_dir, cfg, args, "build", output_files)
    if encryption_result == 1:
        return 1

    output_files["integrity_manifest.json"] = out / "integrity_manifest.json"
    manifest = build_integrity_manifest(
        {
            k: v
            for k, v in output_files.items()
            if k not in {"integrity_manifest.json", "dashboard/dashboard_data.json"}
        }
    )
    write_integrity_manifest(out / "integrity_manifest.json", manifest)
    if getattr(args, "encrypt", False) or cfg.security_encrypt_outputs:
        integrity_targets = {"integrity_manifest.json": out / "integrity_manifest.json"}
        integrity_status = _encrypt_outputs(
            project_dir,
            cfg,
            args,
            "build-integrity",
            integrity_targets,
        )
        if integrity_status == 1:
            return 1
        output_files.update(integrity_targets)
    write_dashboard(
        out / "dashboard",
        {
            "project": cfg.project_name,
            "generated_at": summary["generated_at"],
            "state_counts": state_counts,
            "matrix_rows": matrix_rows,
            "gaps": gap_rows,
            "trend": trend_payload,
            "integrity_manifest": manifest,
            "input_sources": input_manifest,
        },
    )
    _set_mode_paths_private([out / "review_packet.html"])
    _set_private_permissions(out / "dashboard" / "dashboard_data.json", is_dir=False)
    _set_mode_paths_private(output_files.values())
    _set_private_permissions(out, is_dir=True)

    valid_manifest, manifest_issues = verify_file_integrity(manifest, base_dir=out)
    if not valid_manifest:
        print("Integrity build-time check failed:")
        for issue in manifest_issues:
            print(f"- {issue}")
        _append_audit_entry(
            project_dir,
            "build_integrity_failed",
            {"project": cfg.project_name, "issues": manifest_issues},
        )
        return 1

    package_path = None
    if getattr(args, "package", None):
        package_files = dict(output_files)
        bundle = out / "security_bundle.json"
        if bundle.exists():
            package_files["security_bundle.json"] = bundle
        try:
            package_path = _write_release_package(Path(args.package), out, package_files)
            print(f"Review package written to {package_path}")
        except Exception as exc:
            print(f"Package generation failed: {exc}")
            _append_audit_entry(
                project_dir,
                "build_package_failed",
                {"project": cfg.project_name, "error": str(exc)},
            )
            return 1

    _append_audit_entry(
        project_dir,
        "build_completed",
        {
            "project": cfg.project_name,
            "encrypted": bool(getattr(args, "encrypt", False) or cfg.security_encrypt_outputs),
            "package": _format_audit_path(package_path),
        },
    )
    print(f"Build complete -> {out}")
    return 0


def cmd_snapshot(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).resolve()
    cfg = load_project_config(project_dir)
    out = project_dir / "out"
    readiness_path = out / "readiness_summary.json"
    if not readiness_path.exists():
        print("Run build first")
        return 1

    payload = json.loads(readiness_path.read_text(encoding="utf-8"))
    payload.update(
        {
            "snapshot_id": args.snapshot_id or f"SNAP-{dt.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            "reviewer": args.reviewer,
            "notes": args.notes,
        }
    )
    snapshot_path = store_snapshot(project_dir, payload)
    _append_audit_entry(
        project_dir,
        "snapshot_created",
        {"project": cfg.project_name, "snapshot_path": str(snapshot_path)},
    )
    print(f"Snapshot saved: {payload['snapshot_id']}")
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).resolve()
    out = project_dir / "out"
    if not (out / "control_to_evidence_matrix.csv").exists():
        print("Run build first")
        return 1

    matrix_rows = []
    with (out / "control_to_evidence_matrix.csv").open(newline="", encoding="utf-8") as f:
        matrix_rows = list(csv.DictReader(f))
    gap_rows = []
    with (out / "missing_evidence_gaps.csv").open(newline="", encoding="utf-8") as f:
        gap_rows = list(csv.DictReader(f))
    input_rows = _read_input_manifest_csv(out)
    integrity = {}
    manifest_path = out / "integrity_manifest.json"
    if manifest_path.exists():
        integrity = json.loads(manifest_path.read_text(encoding="utf-8"))

    state_counts = {}
    for row in matrix_rows:
        state_counts[row["state"]] = state_counts.get(row["state"], 0) + 1

    trend_payload = json.loads((out / "review_packet.json").read_text(encoding="utf-8")).get("trend", {})

    write_dashboard(
        out / "dashboard",
        {
            "project": str(project_dir.name),
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "state_counts": state_counts,
            "matrix_rows": matrix_rows,
            "gaps": gap_rows,
            "trend": trend_payload,
            "input_sources": input_rows,
            "integrity_manifest": integrity,
        },
    )
    _set_private_permissions(out / "dashboard" / "index.html")
    _set_private_permissions(out / "dashboard", is_dir=True)
    print(f"Dashboard written to {out / 'dashboard' / 'index.html'}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).resolve()
    cfg = load_project_config(project_dir)
    strict_mode = bool(getattr(args, "strict", False) or cfg.security_strict_mode)
    out = project_dir / "out"
    if strict_mode and not _require_clean_security_posture(project_dir, cfg, args, operation="export"):
        return 1
    md = out / "review_packet.md"
    if not md.exists():
        print("Run build first")
        return 1

    outputs: Dict[str, Path] = {}
    if args.format in {"md", "all"}:
        print(f"Markdown packet: {md}")
        outputs["review_packet_md"] = md
    if args.format in {"json", "all"}:
        print(f"JSON packet: {out / 'review_packet.json'}")
        outputs["review_packet_json"] = out / "review_packet.json"
    if args.format in {"html", "all"}:
        html_file = out / "review_packet.html"
        if not html_file.exists():
            write_review_packet_html(html_file, md.read_text(encoding="utf-8"))
        print(f"HTML packet: {html_file}")
        outputs["review_packet_html"] = html_file

    if strict_mode:
        manifest_path = out / "integrity_manifest.json"
        if not manifest_path.exists():
            print("Integrity manifest missing; run build before export for strict mode verification.")
            return 1
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        valid_manifest, manifest_issues = verify_file_integrity(manifest, base_dir=out)
        if not valid_manifest:
            print("Export blocked by integrity mismatch:")
            for issue in manifest_issues:
                print(f"- {issue}")
            _append_audit_entry(
                project_dir,
                "export_blocked",
                {"project": cfg.project_name, "issues": manifest_issues},
            )
            return 1

    encryption_result = _encrypt_outputs(project_dir, cfg, args, "export", outputs)
    if encryption_result == 1:
        return 1
    _append_audit_entry(
        project_dir,
        "export_completed",
        {"project": cfg.project_name, "format": args.format, "strict_mode": strict_mode},
    )
    return 0


def cmd_protect(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).resolve()
    cfg = load_project_config(project_dir)
    passphrase = _resolve_passphrase(project_dir, cfg, args)
    if not passphrase:
        return 1

    src = Path(args.input)
    if not src.exists():
        print(f"Input not found: {src}")
        return 1
    output = Path(args.output) if args.output else src.with_suffix(src.suffix + ".enc")
    try:
        encrypt_file(src, output, passphrase)
    except EncryptionError as exc:
        print(f"Encryption failed: {exc}")
        return 1
    _set_private_permissions(output)
    _append_audit_entry(
        project_dir,
        "protect_completed",
        {"project": cfg.project_name, "input": str(src), "output": str(output)},
    )
    print(f"Protected artifact written to: {output}")
    return 0


def cmd_unprotect(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).resolve()
    cfg = load_project_config(project_dir)
    passphrase = _resolve_passphrase(project_dir, cfg, args)
    if not passphrase:
        return 1

    src = Path(args.input)
    if not src.exists():
        print(f"Input not found: {src}")
        return 1
    output = Path(args.output) if args.output else src.with_suffix(".decrypted")
    try:
        decrypt_file(src, output, passphrase)
    except EncryptionError as exc:
        print(f"Decryption failed: {exc}")
        return 1
    _set_private_permissions(output)
    _append_audit_entry(
        project_dir,
        "unprotect_completed",
        {"project": cfg.project_name, "input": str(src), "output": str(output)},
    )
    print(f"Decrypted artifact written to: {output}")
    return 0


def cmd_sample(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).resolve()
    cfg = load_project_config(project_dir)
    cmd_init(args)

    root = _project_root()
    data_dir = project_dir / ".evidence_graph" / "data"
    for src in (root / "templates").glob("*.csv"):
        shutil.copy2(src, data_dir / src.name)
    for src in (root / "templates").glob("*.yaml"):
        if src.name == "review_snapshot.yaml":
            continue
        shutil.copy2(src, data_dir / src.name)

    _secure_project_paths(project_dir)
    _append_audit_entry(project_dir, "sample_data_created", {"project": cfg.project_name})
    print(f"Sample data created under {data_dir}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).resolve()
    checks_ok = True

    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = project_dir / manifest_path
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        valid_manifest, manifest_issues = verify_file_integrity(manifest, base_dir=manifest_path.parent)
        if not valid_manifest:
            checks_ok = False
            print("Integrity manifest check failed:")
            for issue in manifest_issues:
                print(f"- {issue}")
        else:
            print(f"Integrity manifest OK: {manifest_path}")
    else:
        print(f"Integrity manifest not found: {manifest_path}")
        checks_ok = False

    snapshot_path = Path(args.snapshot)
    if not snapshot_path.is_absolute():
        snapshot_path = project_dir / snapshot_path
    if snapshot_path.exists():
        snapshot_payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
        previous_payload = None
        integrity = snapshot_payload.get("integrity", {})
        previous_signature = None
        if isinstance(integrity, dict):
            previous_signature = integrity.get("previous_snapshot_signature")
            if previous_signature:
                prev_path = _snapshot_signature_lookup(project_dir / ".evidence_graph" / "snapshots", str(previous_signature))
                if prev_path and prev_path.exists():
                    previous_payload = json.loads(prev_path.read_text(encoding="utf-8"))
        snapshot_issues = verify_snapshot_chain(snapshot_payload, previous_payload)
        if snapshot_issues:
            checks_ok = False
            print(f"Snapshot chain check failed for {snapshot_path}:")
            for issue in snapshot_issues:
                print(f"- {issue}")
        else:
            print(f"Snapshot chain OK: {snapshot_path}")
    else:
        print(f"Snapshot not found: {snapshot_path}")
        checks_ok = False

    _append_audit_entry(
        project_dir,
        "verify_completed",
        {"project": project_dir.name, "manifest": str(manifest_path), "snapshot": str(snapshot_path), "ok": checks_ok},
    )
    return 0 if checks_ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Evidence graph tool for local policy-to-evidence mapping")
    sub = parser.add_subparsers(dest="command", required=True)

    init_cmd = sub.add_parser("init", help="Initialize local project")
    _add_project_option(init_cmd)
    init_cmd.set_defaults(func=cmd_init)

    generate_passphrase_cmd = sub.add_parser("generate-passphrase", help="Generate a local strong passphrase")
    _add_project_option(generate_passphrase_cmd)
    generate_passphrase_cmd.add_argument(
        "--length",
        default=48,
        type=int,
        help="Passphrase length for generated value (minimum 32).",
    )
    generate_passphrase_cmd.add_argument(
        "--output",
        default=None,
        help="Write passphrase into this file (private permissions are enforced).",
    )
    generate_passphrase_cmd.set_defaults(func=cmd_generate_passphrase)

    validate_cmd = sub.add_parser("validate", help="Validate imported files")
    _add_project_option(validate_cmd)
    validate_cmd.add_argument(
        "--strict",
        action="store_true",
        help="Treat PHI-like findings as hard failures.",
    )
    validate_cmd.set_defaults(func=cmd_validate)

    build_cmd = sub.add_parser("build", help="Build evidence graph outputs")
    _add_project_option(build_cmd)
    build_cmd.add_argument("--previous-snapshot", default=None)
    build_cmd.add_argument("--package", default=None)
    _add_security_args(build_cmd)
    build_cmd.set_defaults(func=cmd_build)

    snapshot_cmd = sub.add_parser("snapshot", help="Save readiness snapshot")
    _add_project_option(snapshot_cmd)
    snapshot_cmd.add_argument("--snapshot-id", default=None)
    snapshot_cmd.add_argument("--reviewer", default="Practice Owner")
    snapshot_cmd.add_argument("--notes", default="")
    snapshot_cmd.set_defaults(func=cmd_snapshot)

    dashboard_cmd = sub.add_parser("dashboard", help="Generate local dashboard")
    _add_project_option(dashboard_cmd)
    dashboard_cmd.set_defaults(func=cmd_dashboard)

    export_cmd = sub.add_parser("export", help="Export packet")
    _add_project_option(export_cmd)
    export_cmd.add_argument("--format", choices=["md", "json", "html", "all"], default="all")
    _add_security_args(export_cmd)
    export_cmd.set_defaults(func=cmd_export)

    protect_cmd = sub.add_parser("protect", help="Encrypt a file artifact with local key material")
    _add_project_option(protect_cmd)
    protect_cmd.add_argument("--input", required=True)
    protect_cmd.add_argument("--output", default=None)
    protect_cmd.add_argument("--passphrase-env", default=None)
    protect_cmd.add_argument("--passphrase-file", default=None)
    protect_cmd.set_defaults(func=cmd_protect)

    audit_cmd = sub.add_parser("security-audit", help="Run a local security readiness and privacy posture check")
    _add_project_option(audit_cmd)
    _add_security_args(audit_cmd)
    audit_cmd.set_defaults(func=cmd_security_audit)

    unprotect_cmd = sub.add_parser("unprotect", help="Decrypt an encrypted artifact")
    _add_project_option(unprotect_cmd)
    unprotect_cmd.add_argument("--input", required=True)
    unprotect_cmd.add_argument("--output", default=None)
    unprotect_cmd.add_argument("--passphrase-env", default=None)
    unprotect_cmd.add_argument("--passphrase-file", default=None)
    unprotect_cmd.set_defaults(func=cmd_unprotect)

    sample_cmd = sub.add_parser("sample", help="Create realistic sample data")
    _add_project_option(sample_cmd)
    sample_cmd.set_defaults(func=cmd_sample)

    verify_cmd = sub.add_parser("verify", help="Verify output integrity and snapshot chain")
    _add_project_option(verify_cmd)
    verify_cmd.add_argument("--manifest", default="out/integrity_manifest.json")
    verify_cmd.add_argument("--snapshot", default=".evidence_graph/snapshots/latest.json")
    verify_cmd.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
