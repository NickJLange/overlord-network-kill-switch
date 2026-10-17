import pytest
from unittest.mock import patch, MagicMock
from fastapi import HTTPException

pytestmark = pytest.mark.unit


class TestUbiquitiOverlord:
    """Unit tests for UbiquitiOverlord class."""

    @patch("ubiquity.ubiquity.requests.session")
    def test_init(self, mock_session, mock_app_config):
        """Test UbiquitiOverlord initialization."""
        from ubiquity.ubiquity import UbiquitiOverlord

        overlord = UbiquitiOverlord(app_config=mock_app_config)

        assert overlord.controller == "192.168.1.1"
        assert overlord.ubiquiti_api_key == "test_api_key"
        assert "kids_devices" in overlord.macs
        assert overlord.logged_in is False

    @patch("ubiquity.ubiquity.requests.session")
    def test_first_connect_with_api_key(self, mock_session_class, mock_app_config):
        """Test first_connect sets up session with API key."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        from ubiquity.ubiquity import UbiquitiOverlord

        overlord = UbiquitiOverlord(app_config=mock_app_config)
        overlord.first_connect()

        assert overlord.logged_in is True
        mock_session.headers.update.assert_called_with(
            {"X-API-KEY": "test_api_key"}
        )

    @patch("ubiquity.ubiquity.requests.session")
    def test_first_connect_without_api_key(self, mock_session, mock_app_config):
        """Test first_connect raises error without API key."""
        mock_app_config["ubiquiti_api_key"] = None
        from ubiquity.ubiquity import UbiquitiOverlord

        overlord = UbiquitiOverlord(app_config=mock_app_config)

        with pytest.raises(HTTPException) as exc_info:
            overlord.first_connect()
        assert exc_info.value.status_code == 401

    @patch("ubiquity.ubiquity.requests.session")
    def test_parse_firewall_rules(
        self, mock_session_class, mock_app_config, mock_ubiquiti_session
    ):
        """Test parsing firewall rules from controller."""
        mock_session_class.return_value = mock_ubiquiti_session
        from ubiquity.ubiquity import UbiquitiOverlord

        overlord = UbiquitiOverlord(app_config=mock_app_config)
        overlord.first_connect()
        overlord.parse_firewall_rules()

        assert overlord.firewall_rules["Block_Gaming"]["_id"] == "rule1"
        assert overlord.firewall_rules["Block_Gaming"]["enabled"] is True
        assert overlord.last_rules_check is not None

    @patch("ubiquity.ubiquity.requests.session")
    def test_status_rule(
        self, mock_session_class, mock_app_config, mock_ubiquiti_session
    ):
        """Test getting firewall rule status."""
        mock_session_class.return_value = mock_ubiquiti_session
        from ubiquity.ubiquity import UbiquitiOverlord

        overlord = UbiquitiOverlord(app_config=mock_app_config)
        overlord.first_connect()
        overlord.parse_firewall_rules()

        result = overlord.status_rule("Block_Gaming")

        assert result == {"status": True}

    @patch("ubiquity.ubiquity.requests.session")
    def test_change_rule_enable(
        self, mock_session_class, mock_app_config, mock_ubiquiti_session
    ):
        """Test enabling a firewall rule."""
        mock_session_class.return_value = mock_ubiquiti_session
        from ubiquity.ubiquity import UbiquitiOverlord

        overlord = UbiquitiOverlord(app_config=mock_app_config)
        overlord.first_connect()
        overlord.parse_firewall_rules()

        result = overlord.change_rule("enabled", "Block_Gaming")

        assert result["status"] is True
        mock_ubiquiti_session.put.assert_called_once()

    @patch("ubiquity.ubiquity.requests.session")
    def test_change_rule_disable(
        self, mock_session_class, mock_app_config, mock_ubiquiti_session
    ):
        """Test disabling a firewall rule."""
        mock_session_class.return_value = mock_ubiquiti_session
        from ubiquity.ubiquity import UbiquitiOverlord

        overlord = UbiquitiOverlord(app_config=mock_app_config)
        overlord.first_connect()
        overlord.parse_firewall_rules()

        overlord.change_rule("disabled", "Block_Social")

        mock_ubiquiti_session.put.assert_called_once()
        call_args = mock_ubiquiti_session.put.call_args
        payload = call_args[1]["json"]
        assert payload[0]["enabled"] is False

    @patch("ubiquity.ubiquity.requests.session")
    def test_change_rule_invalid_status(
        self, mock_session_class, mock_app_config, mock_ubiquiti_session
    ):
        """Test changing rule with invalid status raises error."""
        mock_session_class.return_value = mock_ubiquiti_session
        from ubiquity.ubiquity import UbiquitiOverlord

        overlord = UbiquitiOverlord(app_config=mock_app_config)
        overlord.first_connect()

        with pytest.raises(HTTPException) as exc_info:
            overlord.change_rule("invalid", "Block_Gaming")
        assert exc_info.value.status_code == 400

    @patch("ubiquity.ubiquity.requests.session")
    def test_change_rule_invalid_rule(
        self, mock_session_class, mock_app_config, mock_ubiquiti_session
    ):
        """Test changing non-existent rule raises error."""
        mock_session_class.return_value = mock_ubiquiti_session
        from ubiquity.ubiquity import UbiquitiOverlord

        overlord = UbiquitiOverlord(app_config=mock_app_config)
        overlord.first_connect()

        with pytest.raises(HTTPException) as exc_info:
            overlord.change_rule("enabled", "Nonexistent_Rule")
        assert exc_info.value.status_code == 400

    @patch("ubiquity.ubiquity.requests.session")
    def test_change_device_block(
        self, mock_session_class, mock_app_config, mock_ubiquiti_session
    ):
        """Test blocking a device."""
        mock_session_class.return_value = mock_ubiquiti_session
        from ubiquity.ubiquity import UbiquitiOverlord

        overlord = UbiquitiOverlord(app_config=mock_app_config)
        overlord.first_connect()

        result = overlord.change_device("offline", "kids_devices")

        assert result == {"status": "offline"}
        mock_ubiquiti_session.post.assert_called_once()
        call_args = mock_ubiquiti_session.post.call_args
        payload = call_args[1]["json"]
        assert payload["cmd"] == "block-sta"
        assert payload["mac"] == "aa:bb:cc:dd:ee:ff"

    @patch("ubiquity.ubiquity.requests.session")
    def test_change_device_unblock(
        self, mock_session_class, mock_app_config, mock_ubiquiti_session
    ):
        """Test unblocking a device."""
        mock_session_class.return_value = mock_ubiquiti_session
        from ubiquity.ubiquity import UbiquitiOverlord

        overlord = UbiquitiOverlord(app_config=mock_app_config)
        overlord.first_connect()

        result = overlord.change_device("online", "kids_devices")

        assert result == {"status": "online"}
        call_args = mock_ubiquiti_session.post.call_args
        payload = call_args[1]["json"]
        assert payload["cmd"] == "unblock-sta"

    @patch("ubiquity.ubiquity.requests.session")
    def test_change_device_not_found(
        self, mock_session_class, mock_app_config, mock_ubiquiti_session
    ):
        """Test changing non-existent device raises error."""
        mock_session_class.return_value = mock_ubiquiti_session
        from ubiquity.ubiquity import UbiquitiOverlord

        overlord = UbiquitiOverlord(app_config=mock_app_config)
        overlord.first_connect()

        with pytest.raises(HTTPException) as exc_info:
            overlord.change_device("offline", "nonexistent_device")
        assert exc_info.value.status_code == 404

    @patch("ubiquity.ubiquity.requests.session")
    def test_shutdown(self, mock_session_class, mock_app_config, mock_ubiquiti_session):
        """Test shutdown closes session."""
        mock_session_class.return_value = mock_ubiquiti_session
        from ubiquity.ubiquity import UbiquitiOverlord

        overlord = UbiquitiOverlord(app_config=mock_app_config)
        overlord.first_connect()
        overlord.shutdown()

        assert overlord.logged_in is False
        mock_ubiquiti_session.close.assert_called_once()

    @patch("ubiquity.ubiquity.requests.session")
    def test_rules_cache_freshness(
        self, mock_session_class, mock_app_config, mock_ubiquiti_session
    ):
        """Test that rules are refreshed when stale."""
        mock_session_class.return_value = mock_ubiquiti_session
        from ubiquity.ubiquity import UbiquitiOverlord
        from datetime import datetime, timedelta

        overlord = UbiquitiOverlord(app_config=mock_app_config)
        overlord.first_connect()
        overlord.parse_firewall_rules()

        overlord.last_rules_check = datetime.now() - timedelta(seconds=120)
        overlord.check_rules_freshness()

        assert mock_ubiquiti_session.get.call_count == 2


@pytest.fixture
def rule_api(mock_app_config, monkeypatch):
    """Exercise HTTP routes against a controller stub; no firewall evaluation."""
    from copy import deepcopy
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from ubiquity import ubiquity

    rules = [
        {"_id": "youtube", "name": "Allow_YouTube_Approved", "enabled": False},
        {"_id": "internet", "name": "Allow_Internet_Approved", "enabled": True},
        {"_id": "baseline", "name": "Restricted_Default", "enabled": True},
    ]
    mock_app_config["ubiquiti_rules"] = {
        "Allow_YouTube_Approved": {}, "Allow_Internet_Approved": {}
    }
    session = MagicMock()

    def read_rules(*args, **kwargs):
        return MagicMock(status_code=200, json=lambda: deepcopy(rules))

    def update_rules(url, json, **kwargs):
        for update in json:
            assert set(update) == {"_id", "enabled"}
            next(rule for rule in rules if rule["_id"] == update["_id"]).update(update)
        return MagicMock(status_code=200)

    session.get.side_effect = read_rules
    session.put.side_effect = update_rules
    monkeypatch.setattr(ubiquity.requests, "session", lambda: session)
    monkeypatch.setattr(ubiquity, "udm", ubiquity.UbiquitiOverlord(app_config=mock_app_config))
    app = FastAPI()
    app.include_router(ubiquity.router)
    with TestClient(app) as client:
        yield client, rules, session


def test_allow_rule_controls_do_not_change_baseline_or_other_exceptions(rule_api):
    client, rules, session = rule_api
    assert client.get("/ubiquiti/status_rule/Allow_YouTube_Approved").json() == {"status": False}
    # Re-created rule has a different ID while Overlord's status cache is fresh.
    rules[0]["_id"] = "replacement-youtube"
    assert client.get("/ubiquiti/enable_rule/Allow_YouTube_Approved").json() == {"status": True}
    assert rules[0]["enabled"] is True
    assert client.get("/ubiquiti/disable_rule/Allow_YouTube_Approved").json() == {"status": False}
    assert [rule["enabled"] for rule in rules] == [False, True, True]
    # Neither unknown names/identities nor an unconfigured baseline can be toggled.
    for name in ("Restricted_Default", "unknown", "02:00:00:00:00:01"):
        assert client.get(f"/ubiquiti/disable_rule/{name}").status_code == 400
        assert client.get(f"/ubiquiti/status_rule/{name}").status_code == 400
    assert [rule["enabled"] for rule in rules] == [False, True, True]


@pytest.mark.parametrize("change", ["removed", "renamed", "duplicate"])
def test_rule_changes_reject_missing_or_ambiguous_names(rule_api, change):
    client, rules, session = rule_api
    assert client.get("/ubiquiti/status_rule/Allow_YouTube_Approved").status_code == 200
    if change == "removed":
        rules.pop(0)
    elif change == "renamed":
        rules[0]["name"] = "Different_Policy"
    else:
        rules.append({**rules[0], "_id": "duplicate-youtube"})
    before = [rule.copy() for rule in rules]
    response = client.get("/ubiquiti/enable_rule/Allow_YouTube_Approved")
    assert response.status_code == 409
    assert rules == before
    assert client.get("/ubiquiti/status_rule/Allow_YouTube_Approved").status_code == 409


@pytest.mark.parametrize("failure", ["http", "timeout", "ignored", "readback", "removed"])
def test_failed_revoke_never_reports_success_and_status_can_recover(rule_api, failure):
    import requests

    client, rules, session = rule_api
    path = "/ubiquiti/status_rule/Allow_Internet_Approved"
    assert client.get(path).json() == {"status": True}
    original_read = session.get.side_effect
    original_update = session.put.side_effect

    def fail_update(*args, **kwargs):
        if failure == "http":
            return MagicMock(status_code=503)
        if failure == "timeout":
            # The controller may apply an update even when the response is lost.
            original_update(*args, **kwargs)
            raise requests.Timeout()
        if failure == "readback":
            original_update(*args, **kwargs)
            session.get.side_effect = requests.Timeout()
        if failure == "removed":
            rules.pop(1)
        return MagicMock(status_code=200)

    session.put.side_effect = fail_update
    response = client.get("/ubiquiti/disable_rule/Allow_Internet_Approved")
    if failure == "readback":
        assert response.status_code == 502
    else:
        assert response.json() == {"status": "unknown"}
    assert rules[-1]["enabled"] is True  # Baseline untouched, even on failed revoke.
    session.get.side_effect = original_read
    observed = client.get(path)
    if failure == "removed":
        assert observed.status_code == 409
    else:
        assert observed.json() == {"status": failure in ("http", "ignored")}


def test_cold_refresh_authenticates_and_discards_deleted_rules(rule_api):
    client, rules, session = rule_api
    rules.append({"_id": "unrelated-unnamed-policy", "enabled": False})
    assert client.get("/ubiquiti/refresh").status_code == 200
    assert session.get.call_args.kwargs["timeout"] is not None
    assert session.headers.update.call_args.args == ({"X-API-KEY": "test_api_key"},)
    rules.pop(0)
    assert client.get("/ubiquiti/refresh").status_code == 200
    assert client.get("/ubiquiti/status_rule/Allow_YouTube_Approved").status_code == 409


@pytest.mark.parametrize("response", [None, {}, [{"name": "Allow_YouTube_Approved", "enabled": "false"}]])
def test_malformed_refresh_does_not_reuse_previous_rule_state(rule_api, response):
    client, rules, session = rule_api
    path = "/ubiquiti/status_rule/Allow_Internet_Approved"
    assert client.get(path).json() == {"status": True}
    session.get.side_effect = lambda *args, **kwargs: MagicMock(status_code=200, json=lambda: response)
    assert client.get("/ubiquiti/refresh").status_code == 502
    assert client.get(path).status_code == 502
    assert client.get("/ubiquiti/disable_rule/Allow_Internet_Approved").status_code == 502
    assert rules[1]["enabled"] is True


def test_node_red_rule_messages_confirm_only_observed_boolean_states():
    import shutil
    import subprocess
    from pathlib import Path

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js required to execute Node-RED function contracts")
    result = subprocess.run(
        [node, "-e", """
const assert = require('node:assert/strict');
const nodes = JSON.parse(require('node:fs').readFileSync('node_red_flows/dns.json'));
const run = id => new Function('msg', 'flow', 'node', nodes.find(n => n.id === id).func);
const request = run('de40f7116f0940db');
const response = run('e2bffb8fdc17ad70');
const flow = {get: () => 'http://controller.invalid'};
const errors = [];
const node = {error: (...args) => errors.push(args), warn: () => {}};
for (const [input, enabled] of [[true, true], ['true', true], [false, false], ['false', false]]) {
    const msg = request({verb: 'change_rule', target: 'Allow YouTube', payload: input}, flow, node);
    assert.equal(msg.method, 'GET');
    assert.equal(msg.url, `http://controller.invalid/ubiquiti/${enabled ? 'enable' : 'disable'}_rule/Allow%20YouTube`);
    const out = response({...msg, statusCode: 200, payload: {status: enabled}}, flow, node);
    assert.deepEqual(out, {payload: enabled, topic: 'stat/router_controller/status_rule/Allow YouTube'});
}
assert.equal(errors.length, 0);
for (const payload of [undefined, 'unknown', 0, 1, 'TRUE', {}, '']) {
    assert.equal(request({verb: 'change_rule', target: 'Allow_YouTube', payload}, flow, node), null);
}
for (const [statusCode, payload] of [[503, {status: false}], [200, {status: 'unknown'}],
        [200, {status: 'false'}], [200, {}], [200, null]]) {
    assert.equal(response({verb: 'change_rule', target: 'Allow_YouTube', statusCode, payload}, flow, node), null);
}
assert.equal(errors.length, 12);
// Legacy device command direction and rule status queries remain unchanged.
for (const [payload, route] of [['online', 'enable_device'], ['offline', 'disable_device']]) {
    assert.equal(request({verb: 'change_device', target: 'kids', payload}, flow, node).url,
        `http://controller.invalid/ubiquiti/${route}/kids`);
}
assert.equal(request({verb: 'status_rule', target: 'Allow_YouTube'}, flow, node).url,
    'http://controller.invalid/ubiquiti/status_rule/Allow_YouTube');
console.log('UniFi Node-RED message contracts passed');
"""],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
