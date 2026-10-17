"""Lab preparation must reject configuration drift before starting services."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("drift", ["missing-broker", "renamed-endpoint", "external-url", "bare-ip"])
def test_prepare_rejects_drift_without_overwriting_valid_flow(tmp_path, drift):
    script = tmp_path / "tests/lab/prepare.py"
    script.parent.mkdir(parents=True)
    shutil.copy(ROOT / "tests/lab/prepare.py", script)
    source = tmp_path / "node_red_flows/dns.json"
    source.parent.mkdir()
    nodes = json.loads((ROOT / "node_red_flows/dns.json").read_text())
    source.write_text(json.dumps(nodes))
    subprocess.run([sys.executable, str(script)], check=True, timeout=5)
    output = tmp_path / ".amp/lab/flows.json"
    valid = output.read_text()
    assert {n["broker"] for n in json.loads(valid) if n["type"] == "mqtt-broker"} == {"mqtt"}
    assert valid.count("http://overlord:19000") == 4

    if drift == "missing-broker":
        nodes = [n for n in nodes if n["type"] != "mqtt-broker"]
    elif drift == "renamed-endpoint":
        rule = next(r for n in nodes for r in n.get("rules", []) if r.get("p") == "endpoint")
        rule["p"] = "renamed_endpoint"
    else:
        node = next(n for n in nodes if n["type"] == "http request")
        node["url"] = "https://outside-lab.invalid/api" if drift == "external-url" else "192.0.2.10"
    source.write_text(json.dumps(nodes))
    result = subprocess.run([sys.executable, str(script)], capture_output=True, timeout=5)
    assert result.returncode != 0
    assert output.read_text() == valid
