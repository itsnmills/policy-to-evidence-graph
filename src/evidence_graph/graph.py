from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Tuple


@dataclass
class Graph:
    nodes: Dict[str, dict]
    edges: List[Tuple[str, str, str, str]]


def build_graph(controls, policies, procedures, systems, vendors, risks, evidence_map):
    nodes = defaultdict(dict)
    edges: List[Tuple[str, str, str, str]] = []

    for c_id, control in controls.items():
        nodes["control"][c_id] = {
            "id": c_id,
            "title": control.title,
            "type": "control",
        }

    for p_id, policy in policies.items():
        nodes["policy"][p_id] = {
            "id": p_id,
            "title": policy.title,
            "type": "policy",
            "status": policy.status,
        }
        for c_id in policy.control_ids:
            if c_id in controls:
                edges.append(("policy", p_id, "implements", c_id))

    for pr_id, procedure in procedures.items():
        nodes["procedure"][pr_id] = {
            "id": pr_id,
            "title": procedure.title,
            "type": "procedure",
        }
        for c_id in procedure.control_ids:
            if c_id in controls:
                edges.append(("procedure", pr_id, "implements", c_id))
        for p_id in procedure.policy_ids:
            if p_id in policies:
                edges.append(("procedure", pr_id, "references", p_id))

    for s_id, system in systems.items():
        nodes["system"][s_id] = {"id": s_id, "name": system.name, "type": "system"}
        for c_id in system.controls:
            if c_id in controls:
                edges.append(("system", s_id, "affects", c_id))

    for v_id, vendor in vendors.items():
        nodes["vendor"][v_id] = {"id": v_id, "name": vendor.name, "type": "vendor"}
        for c_id in vendor.controls:
            if c_id in controls:
                edges.append(("vendor", v_id, "affects", c_id))

    for r_id, risk in risks.items():
        nodes["risk"][r_id] = {"id": r_id, "title": risk.title, "type": "risk"}
        for c_id in risk.control_ids:
            if c_id in controls:
                edges.append(("risk", r_id, "mitigates", c_id))

    for control_id, evidence_ids in evidence_map.items():
        for evidence_id in evidence_ids:
            edges.append(("control", control_id, "has_evidence", evidence_id))

    return Graph(nodes=dict(nodes), edges=edges)
