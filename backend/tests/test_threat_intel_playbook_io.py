"""threat_intel_playbook_io：展平与校验（不连 Neo4j）。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services import threat_intel_playbook_io


def test_iter_playbook_objects_flattens_nested_list() -> None:
    raw = [{"a": 1}, [{"b": 2}, {"c": 3}]]
    out = list(threat_intel_playbook_io.iter_playbook_objects(raw))
    assert len(out) == 3
    assert out[0]["a"] == 1
    assert out[1]["b"] == 2


def test_load_playbook_rows_from_repo_file() -> None:
    rows = threat_intel_playbook_io.load_playbook_rows(threat_intel_playbook_io.PLAYBOOKS_DEFAULT_PATH)
    assert len(rows) >= 6
    names = {r["threat_name"] for r in rows}
    assert "N33_API_BOLA_Exploit" in names
    assert "Nsmf_PDUSession_QoS_Hijack" in names


def test_validate_playbook_row_ok() -> None:
    row = {
        "target_node_type": "NetworkFunction",
        "target_node_name": "NEF",
        "threat_name": "t1",
        "vulnerability_type": "X",
        "description": "d",
        "payload_template": "curl {TARGET_IP}",
    }
    ok, reason = threat_intel_playbook_io.validate_playbook_row(row)
    assert ok and reason == "ok"


def test_validate_playbook_row_missing_key() -> None:
    row = {"threat_name": "x"}
    ok, reason = threat_intel_playbook_io.validate_playbook_row(row)
    assert ok is False
    assert "missing_keys" in reason


def test_load_custom_json_file(tmp_path: Path) -> None:
    p = tmp_path / "p.json"
    p.write_text(
        json.dumps(
            [
                {
                    "target_node_type": "NetworkFunction",
                    "target_node_name": "X",
                    "threat_name": "T1",
                    "vulnerability_type": "v",
                    "description": "d",
                    "payload_template": "p",
                }
            ],
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    rows = threat_intel_playbook_io.load_playbook_rows(p)
    assert len(rows) == 1
    assert rows[0]["threat_name"] == "T1"
