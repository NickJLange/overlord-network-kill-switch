"""Disposable UniFi named-policy API simulator; never a firewall emulator."""

from copy import deepcopy
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException


def authenticate(x_api_key: str = Header(default="")):
    if x_api_key != "local-simulator-only":
        raise HTTPException(401, "Simulator API key required")


app = FastAPI(title="Local UniFi simulator", dependencies=[Depends(authenticate)])
INITIAL_RULES = [
    {"_id": "youtube", "name": "Allow_YouTube_Approved", "enabled": False},
    {"_id": "internet", "name": "Allow_Internet_Approved", "enabled": True},
    {"_id": "baseline", "name": "Restricted_Default", "enabled": True},
]
rules = deepcopy(INITIAL_RULES)
fault = "none"
writes = 0
POLICIES = "/proxy/network/v2/api/site/default/firewall-policies"


@app.get(POLICIES)
async def list_rules():
    return deepcopy(rules)


@app.put(POLICIES + "/batch")
async def update_rules(updates: list[dict]):
    global fault, writes
    writes += 1
    pending_fault, fault = fault, "none"
    if pending_fault == "reject":
        raise HTTPException(503, "Injected controller failure")
    # Model only the single-rule request the client currently sends.
    if len(updates) != 1:
        raise HTTPException(400, "Simulator supports one rule per request")
    update = updates[0]
    if set(update) != {"_id", "enabled"} or type(update["enabled"]) is not bool:
        raise HTTPException(400, "Expected _id and boolean enabled")
    matches = [rule for rule in rules if rule["_id"] == update["_id"]]
    if len(matches) != 1:
        raise HTTPException(404, "Unknown or ambiguous rule ID")
    if pending_fault != "ignore":
        matches[0].update(update)
    return {"meta": {"rc": "ok"}}


@app.get("/__sim/state")
def state():
    return {"rules": deepcopy(rules), "writes": writes, "fault": fault}


@app.post("/__sim/reset")
async def reset():
    global rules, fault, writes
    rules, fault, writes = deepcopy(INITIAL_RULES), "none", 0
    return state()


@app.put("/__sim/fault/{mode}")
async def inject_fault(mode: Literal["none", "reject", "ignore"]):
    global fault
    fault = mode
    return state()


@app.put("/__sim/rules")
async def replace_rules(inventory: list[dict]):
    """Model controller-side deletion, renaming, or duplicate names."""
    global rules
    for rule in inventory:
        if (set(rule) != {"_id", "name", "enabled"}
                or not isinstance(rule["_id"], str)
                or not isinstance(rule["name"], str)
                or type(rule["enabled"]) is not bool):
            raise HTTPException(400, "Invalid rule inventory")
    rules = deepcopy(inventory)
    return state()
