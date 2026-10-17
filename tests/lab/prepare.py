"""Generate local endpoint configuration without editing the production flow."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
target = ROOT / ".amp/lab"
target.mkdir(parents=True, exist_ok=True)
nodes = json.loads((ROOT / "node_red_flows/dns.json").read_text())
for node in nodes:
    if node["type"] == "mqtt-broker":
        node.update(broker="mqtt", port="1883", usetls=False)
    for rule in node.get("rules", []):
        if rule.get("p") == "endpoint" and rule.get("pt") == "flow":
            rule.update(to="http://overlord:19000", tot="str")
(target / "flows.json").write_text(json.dumps(nodes, indent=2) + "\n")
