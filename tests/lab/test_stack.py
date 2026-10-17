"""Real MQTT/Node-RED/HTTP tests against disposable local services only."""

import asyncio
import ssl
from pathlib import Path
from urllib.parse import quote

import aiomqtt
import httpx
import pytest

pytestmark = pytest.mark.integration
CA = Path(__file__).resolve().parents[2] / ".amp/lab/certs/cert.pem"
YOUTUBE = "Allow_YouTube_Approved"
INTERNET = "Allow_Internet_Approved"


@pytest.fixture
def simulator():
    with httpx.Client(
        base_url="https://127.0.0.1:19443", timeout=5,
        verify=ssl.create_default_context(cafile=str(CA)),
        headers={"X-API-KEY": "local-simulator-only"}, trust_env=False,
    ) as client:
        client.post("/__sim/reset").raise_for_status()
        yield client
        client.post("/__sim/reset").raise_for_status()


@pytest.fixture
def api():
    with httpx.Client(base_url="http://127.0.0.1:19001", timeout=10, trust_env=False) as client:
        client.get("/ubiquiti/refresh").raise_for_status()
        yield client


async def receive(client, topic, timeout=6, expected=None):
    async with asyncio.timeout(timeout):
        async for message in client.messages:
            if str(message.topic) == topic and not message.retain:
                payload = message.payload.decode()
                if expected is None or payload == expected:
                    return payload


async def settle(client):
    # The exported flow echoes status through a read path once. Do not mistake
    # that response for the next command's acknowledgement.
    async with asyncio.timeout(10):
        while True:
            try:
                await asyncio.wait_for(anext(client.messages), 1.5)
            except TimeoutError:
                return


@pytest.fixture
async def mqtt_client():
    async with aiomqtt.Client("127.0.0.1", 18883) as client:
        await client.subscribe("stat/#", qos=1)
        # Read-only readiness probe waits for actual Node-RED MQTT subscriptions,
        # using the documented command topic rather than a status feedback loop.
        for _ in range(10):
            await client.publish("cmnd/dns_controller/master/status", "", qos=1)
            try:
                response = await receive(client, "stat/dns_controller/master/status", 2)
                if response in ("true", "false"):
                    break
            except TimeoutError:
                continue
        else:
            pytest.fail("Node-RED did not answer MQTT readiness probes")
        # Let the sample flow's status echo settle before testing new commands.
        await settle(client)
        yield client
        await settle(client)


def enabled(simulator):
    return {r["name"]: r["enabled"] for r in simulator.get("/__sim/state").json()["rules"]}


async def command(client, target, value):
    await client.publish(f"cmnd/router_controller/change_rule/{target}", value, qos=1)
    result = await receive(client, f"stat/router_controller/status_rule/{target}", expected=value)
    await settle(client)
    return result


async def test_mqtt_rule_changes_and_identical_retry(simulator, api, mqtt_client):
    assert await command(mqtt_client, YOUTUBE, "true") == "true"
    assert enabled(simulator) == {YOUTUBE: True, INTERNET: True, "Restricted_Default": True}
    # External drift: the same command must be delivered again, not deduplicated.
    inventory = simulator.get("/__sim/state").json()["rules"]
    inventory[0]["enabled"] = False
    simulator.put("/__sim/rules", json=inventory).raise_for_status()
    assert await command(mqtt_client, YOUTUBE, "true") == "true"
    assert enabled(simulator)[YOUTUBE] is True
    assert await command(mqtt_client, YOUTUBE, "false") == "false"
    assert enabled(simulator) == {YOUTUBE: False, INTERNET: True, "Restricted_Default": True}


@pytest.mark.parametrize("failure", ["reject", "ignore"])
async def test_failed_revoke_has_no_confirmation_and_same_command_can_retry(
    simulator, api, mqtt_client, failure,
):
    simulator.put(f"/__sim/fault/{failure}").raise_for_status()
    await mqtt_client.publish(f"cmnd/router_controller/change_rule/{INTERNET}", "false", qos=1)
    with pytest.raises(TimeoutError):
        await receive(mqtt_client, f"stat/router_controller/status_rule/{INTERNET}", 2.5)
    assert simulator.get("/__sim/state").json()["writes"] == 1
    assert enabled(simulator)[INTERNET] is True
    assert await command(mqtt_client, INTERNET, "false") == "false"
    assert enabled(simulator) == {YOUTUBE: False, INTERNET: False, "Restricted_Default": True}


async def test_malformed_mqtt_and_unconfigured_baseline_never_write(simulator, api, mqtt_client):
    await mqtt_client.publish(f"cmnd/router_controller/change_rule/{YOUTUBE}", "maybe", qos=1)
    with pytest.raises(TimeoutError):
        await receive(mqtt_client, f"stat/router_controller/status_rule/{YOUTUBE}", 2.5)
    assert api.get("/ubiquiti/disable_rule/Restricted_Default").status_code == 400
    assert simulator.get("/__sim/state").json()["writes"] == 0
    assert enabled(simulator)["Restricted_Default"] is True


def test_simulator_rejects_wrong_or_missing_api_key(simulator):
    policies = "/proxy/network/v2/api/site/default/firewall-policies"
    assert simulator.get(policies, headers={"X-API-KEY": "wrong"}).status_code == 401
    del simulator.headers["X-API-KEY"]
    try:
        assert simulator.get(policies).status_code == 401
    finally:
        simulator.headers["X-API-KEY"] = "local-simulator-only"


@pytest.fixture
def pihole():
    # Read Pi-hole directly, independently of Overlord's response and client.
    with httpx.Client(base_url="http://127.0.0.1:18080/api", timeout=5, trust_env=False) as client:
        response = client.post("/auth", json={"password": "local-pihole-only"})
        response.raise_for_status()
        client.headers["X-FTL-SID"] = response.json()["session"]["sid"]
        yield client
        client.post("/dns/blocking", json={"blocking": True, "timer": None}).raise_for_status()
        client.delete("/auth").raise_for_status()


async def dns_command(client, topic, value, status_topic):
    await client.publish(topic, value, qos=1)
    response = await receive(client, status_topic, expected=value)
    await settle(client)
    return response


async def test_mqtt_master_polarity_timers_and_expiry_feedback(api, mqtt_client, pihole):
    status = "stat/dns_controller/master/status"
    permanent = "cmnd/dns_controller/master/perm_change"
    short = "cmnd/dns_controller/master/short_change"
    assert await dns_command(mqtt_client, short, "true", status) == "true"
    observed = pihole.get("/dns/blocking").json()
    assert observed["blocking"] == "disabled"
    assert 290 < observed["timer"] <= 300
    for value, blocking in [("true", "disabled"), ("false", "enabled"), ("false", "enabled")]:
        assert await dns_command(mqtt_client, permanent, value, status) == value
        observed = pihole.get("/dns/blocking").json()
        assert observed["blocking"] == blocking
        assert observed["timer"] is None
    # Timer expiry must reach MQTT without another HomeKit command.
    assert await dns_command(mqtt_client, permanent, "true", status) == "true"
    api.post("/alldns/?timer=1").raise_for_status()
    # A scheduled poll before expiry may legitimately still report bypass ON.
    assert await receive(mqtt_client, status, 15, expected="false") == "false"
    assert pihole.get("/dns/blocking").json()["blocking"] == "enabled"


async def test_mqtt_domain_enable_repairs_disabled_entries(api, mqtt_client, pihole):
    patterns = ["youtube.com", "googlevideo.com"]
    # Start from existing but disabled entries, not the trivial absent case.
    for pattern in patterns:
        path = "/domains/deny/regex/" + quote(pattern, safe="")
        deleted = pihole.delete(path)
        assert deleted.status_code in (204, 404)
        pihole.post("/domains/deny/regex", json={"domain": pattern, "enabled": False}).raise_for_status()
    topic = "cmnd/dns_controller/media/youtube/change"
    status = "stat/dns_controller/media/youtube/status"
    for value in ("true", "true", "false"):
        assert await dns_command(mqtt_client, topic, value, status) == value
        domains = pihole.get("/domains/deny/regex").json()["domains"]
        active = {d["domain"] for d in domains if d["enabled"]}
        if value == "true":
            assert set(patterns) <= active
        else:
            assert not set(patterns) & active
