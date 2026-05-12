from evidence_graph.trends import compare_trends


def test_compare_trends():
    current = {"readiness": {"A": {"state": "ready"}, "B": {"state": "missing"}}}
    previous = {"readiness": {"A": {"state": "partial"}, "B": {"state": "missing"}}}
    payload = compare_trends(current, previous)
    assert "A" in payload["improved"]
    assert "B" not in payload["improved"]
