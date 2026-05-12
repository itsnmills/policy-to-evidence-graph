import subprocess
import os
import sys
from pathlib import Path


def _run_cli(command: list[str], cwd: str) -> subprocess.CompletedProcess[str]:
    project_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(project_root / "src")
    return subprocess.run(
        [sys.executable, "-m", "evidence_graph.cli", *command],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_cli_runs_help(tmp_path):
    p = Path(__file__).resolve().parents[1]
    result = _run_cli(["--help"], str(p))
    assert result.returncode == 0
    assert "Evidence graph" in result.stdout


def test_security_audit_generates_reports(tmp_path):
    p = Path(__file__).resolve().parents[1]
    project = tmp_path / "clinic"
    project.mkdir()

    result = _run_cli(["init", "--project", str(project)], str(p))
    assert result.returncode == 0

    result = _run_cli(["sample", "--project", str(project)], str(p))
    assert result.returncode == 0

    result = _run_cli(["security-audit", "--project", str(project)], str(p))
    assert result.returncode == 0
    assert (project / "out" / "security_audit_report.json").exists()
    assert (project / "out" / "security_audit_report.md").exists()


def test_security_audit_strict_fails_without_required_inputs(tmp_path):
    p = Path(__file__).resolve().parents[1]
    project = tmp_path / "clinic_strict"
    project.mkdir()

    result = _run_cli(["init", "--project", str(project)], str(p))
    assert result.returncode == 0

    # Delete a required file to force a security posture failure.
    (project / ".evidence_graph" / "data" / "policy_register.csv").unlink(missing_ok=True)

    result = _run_cli(["security-audit", "--project", str(project), "--strict"], str(p))
    assert result.returncode == 1
    assert "Security audit failed:" in result.stdout
