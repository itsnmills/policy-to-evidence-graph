from __future__ import annotations

from collections import defaultdict


def map_evidence_to_controls(evidence_items, control_records, system_control_map, vendor_control_map):
    control_map = defaultdict(list)

    for evidence in evidence_items:
        targets = set(evidence.control_ids)

        for system_id in evidence.systems:
            target = system_control_map.get(system_id)
            if target:
                targets.add(target)

        for vendor_id in evidence.vendors:
            target = vendor_control_map.get(vendor_id)
            if target:
                targets.add(target)

        if not targets:
            for control_id, control in control_records.items():
                req_types = set(t.lower() for t in control.required_evidence_types)
                if evidence.evidence_type.lower() in req_types:
                    targets.add(control_id)

        for control_id in sorted(targets):
            control_map[control_id].append(evidence.evidence_id)

    return {control_id: sorted(set(evidence_ids)) for control_id, evidence_ids in control_map.items()}
