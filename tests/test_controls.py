from evidence_graph.models import ControlRecord
from evidence_graph.controls import readiness_from_evidence


def test_readiness_missing_when_no_evidence():
    control = ControlRecord(control_id="C1", title="Control", required_evidence_types=["system_inventory"], criticality="high")
    result = readiness_from_evidence(control, [], {}, 90)
    assert result["state"] == "missing"
    assert result["readiness_score"] == 0
