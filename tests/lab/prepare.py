"""Generate local endpoint configuration without editing the production flow."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
target = ROOT / ".amp/lab"
nodes = json.loads((ROOT / "node_red_flows/dns.json").read_text())
brokers = endpoints = 0
for node in nodes:
    if node["type"] == "mqtt-broker":
        node.update(broker="mqtt", port="1883", usetls=False)
        brokers += 1
    for rule in node.get("rules", []):
        if rule.get("p") == "endpoint" and rule.get("pt") == "flow":
            rule.update(to="http://overlord:19000", tot="str")
            endpoints += 1

# Fail closed when the exported flow changes instead of preserving deployment
# addresses. This validates the current flow format, not arbitrary JavaScript.
if brokers != 1 or endpoints != 4:
    raise ValueError("Unexpected flow layout: expected one broker and four API endpoints")
output = json.dumps(nodes, indent=2) + "\n"
if (set(re.findall(r'https?://[^"\\\s]+', output)) != {"http://overlord:19000"}
        or re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output)
        or "XXXX" in output):
    raise ValueError("Non-lab address remains in generated flow")
target.mkdir(parents=True, exist_ok=True)
(target / "flows.json").write_text(output)
