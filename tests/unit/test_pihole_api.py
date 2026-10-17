"""Pi-hole v6 API regressions, replacing the obsolete pre-v6 tests."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pihole import pihole_router

pytestmark = pytest.mark.unit


@pytest.fixture
def dns_api(monkeypatch, mock_app_config):
    class Device:
        def __init__(self):
            self.domains = {}
            self.blocking = True
            self.timer = None
            self.ignore_write = False
            self.closed = False
            self.domain_management = self
            self.dns_control = self

        def get_domain(self, domain, kind, _):
            record = self.domains.get((kind, domain))
            return {"domains": [deepcopy(record)] if record else []}

        def add_domain(self, domain, kind, _, groups=None, enabled=True):
            if self.ignore_write or (kind, domain) in self.domains:
                return {"error": {"key": "database_error"}}
            self.domains[kind, domain] = {
                "domain": domain, "enabled": enabled, "groups": groups, "comment": "keep",
            }
            return self.get_domain(domain, kind, _)

        def update_domain(self, domain, kind, _, **kwargs):
            if not self.ignore_write:
                self.domains[kind, domain].update(kwargs)
            return self.get_domain(domain, kind, _)

        def delete_domain(self, domain, kind, _):
            if not self.ignore_write:
                self.domains.pop((kind, domain), None)
            return {}

        def set_blocking_status(self, status, timer=None):
            if not self.ignore_write:
                self.blocking, self.timer = status, timer
            return {}

        def get_blocking_status(self):
            return {"blocking": "enabled" if self.blocking else "disabled", "timer": self.timer}

        def close_session(self):
            self.closed = True

    devices = [Device(), Device()]
    mock_app_config["remote_pi_list"] = ["one", "two"]
    factory = Mock(side_effect=lambda url, _: devices[url == "http://two"])
    monkeypatch.setattr("pihole.base.PiHole6Client", factory)
    pihole_router.init(mock_app_config)
    app = FastAPI()
    app.include_router(pihole_router.main_router)
    app.include_router(pihole_router.alldns_router)
    with TestClient(app) as client:
        yield SimpleNamespace(client=client, devices=devices, factory=factory)
    pihole_router.pihole.shutdown()
    pihole_router.all_dns.shutdown()


@pytest.mark.parametrize("target,kind,domains", [
    ("youtube", "deny", ["youtube.com", "googlevideo.com"]),
    ("school", "allow", ["edu.example.com"]),
])
def test_domain_commands_report_observed_state_and_are_repeatable(dns_api, target, kind, domains):
    client = dns_api.client
    for action, expected in [("enable", "true"), ("enable", "true"), ("disable", "false"), ("disable", "false")]:
        response = client.post(f"/pihole/{action}/{target}")
        assert response.status_code == 200
        assert response.json() == {"status": expected}
        assert client.get(f"/pihole/status/{target}").json() == {"status": expected}
        for device in dns_api.devices:
            for domain in domains:
                assert bool(device.domains.get((kind, domain), {}).get("enabled")) == (expected == "true")


def test_enable_existing_disabled_domain_preserves_metadata(dns_api):
    for device in dns_api.devices:
        device.add_domain("edu.example.com", "allow", "regex", groups=[0, 3], enabled=False)
    response = dns_api.client.post("/pihole/enable/school")
    assert response.json() == {"status": "true"}
    for device in dns_api.devices:
        assert device.domains["allow", "edu.example.com"] == {
            "domain": "edu.example.com", "enabled": True, "groups": [0, 3], "comment": "keep",
        }


@pytest.mark.parametrize("action", ["enable", "disable"])
def test_domain_write_mismatch_is_not_success(dns_api, action):
    if action == "disable":
        assert dns_api.client.post("/pihole/enable/youtube").status_code == 200
    dns_api.devices[1].ignore_write = True
    response = dns_api.client.post(f"/pihole/{action}/youtube")
    assert response.status_code == 502
    assert dns_api.client.get("/pihole/status/youtube").json() == {"status": "unknown"}
    dns_api.devices[1].ignore_write = False
    assert dns_api.client.post(f"/pihole/{action}/youtube").json() == {
        "status": "true" if action == "enable" else "false",
    }


def test_permanent_global_commands_do_not_inherit_timers(dns_api):
    client = dns_api.client
    assert client.post("/alldns/?timer=60").json() == {"status": "false"}
    assert all(device.timer == 60 for device in dns_api.devices)
    assert client.delete("/alldns/").json() == {"status": "true"}
    assert all(device.blocking and device.timer is None for device in dns_api.devices)
    assert client.post("/alldns/").json() == {"status": "false"}
    assert all(not device.blocking and device.timer is None for device in dns_api.devices)
    assert client.post("/alldns/?timer=-1").status_code == 422


def test_global_write_mismatch_is_not_success(dns_api):
    dns_api.devices[1].ignore_write = True
    assert dns_api.client.post("/alldns/").status_code == 502
    assert dns_api.client.get("/alldns/").json() == {"status": "unknown"}


def test_rejected_timer_change_is_not_confirmed_by_matching_boolean(dns_api):
    assert dns_api.client.post("/alldns/?timer=60").status_code == 200
    dns_api.devices[1].set_blocking_status = lambda *_: {"error": {"key": "forbidden"}}
    assert dns_api.client.post("/alldns/").status_code == 502
    assert dns_api.devices[1].timer == 60


@pytest.mark.parametrize("path", ["/alldns/", "/pihole/status/youtube"])
def test_failed_connect_never_reports_success_and_can_recover(dns_api, path):
    dns_api.factory.side_effect = RuntimeError("unreachable")
    for _ in range(2):
        assert dns_api.client.get(path).status_code == 503
    dns_api.factory.side_effect = lambda url, _: dns_api.devices[url == "http://two"]
    assert dns_api.client.get(path).status_code == 200


def test_partial_connect_is_not_success_and_shutdown_closes_open_sessions(dns_api):
    dns_api.factory.side_effect = [dns_api.devices[0], RuntimeError("unreachable")]
    assert dns_api.client.post("/pihole/enable/youtube").status_code == 503
    assert not dns_api.devices[0].domains
    pihole_router.pihole.shutdown()
    assert dns_api.devices[0].closed
    assert not pihole_router.pihole.sessions


@pytest.mark.parametrize("path", ["/alldns/", "/pihole/status/youtube"])
def test_empty_device_list_is_unavailable(dns_api, path):
    pihole_router.pihole.piList = []
    pihole_router.all_dns.piList = []
    assert dns_api.client.get(path).status_code == 503


def test_unknown_target_does_not_mutate_devices(dns_api):
    assert dns_api.client.post("/pihole/enable/typo").status_code == 404
    assert all(not device.domains for device in dns_api.devices)
