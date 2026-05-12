from evidence_graph import normalize


def test_split_list():
    assert normalize._split_list("a,b,c") == ["a", "b", "c"]


def test_normalize_policy_rows():
    rows = normalize.normalize_policy_rows([{"policy_id": "P1", "title": "Test", "owner": "You", "status": "active", "updated_at": "2026-05-12", "description": "", "control_ids": "C1, C2"}])
    assert rows[0]["control_ids"] == ["C1", "C2"]
