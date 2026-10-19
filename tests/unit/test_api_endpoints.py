"""
Unit tests for API endpoints.

Includes the controller's configuration and lifespan through TestClient.
External Pi-hole, UniFi and MQTT integration is exercised by the disposable lab.
"""

import pytest
import configparser
from io import BytesIO
from fastapi.testclient import TestClient
from unittest.mock import patch

pytestmark = pytest.mark.unit

PIHOLE_CLIENT_PATCH = "pihole.base.PiHole6Client"


class TestPiholeRouter:
    """Test Pi-hole router functions directly."""

    def test_pihole_router_init(self, mock_app_config):
        """Test pihole_router.init creates instances."""
        with patch(PIHOLE_CLIENT_PATCH):
            from pihole import pihole_router

            pihole_router.init(mock_app_config)

            assert pihole_router.pihole is not None
            assert pihole_router.all_dns is not None


class TestAlldnsRouter:
    """Test all_dns router functions directly."""

    @patch(PIHOLE_CLIENT_PATCH)
    def test_alldns_get(self, mock_client_class, mock_app_config, mock_pihole_client):
        """Test all_dns.get returns status."""
        mock_client_class.return_value = mock_pihole_client
        mock_pihole_client.dns_control.get_blocking_status.return_value = {
            "blocking": "enabled",
            "timer": None,
        }

        from pihole.alldns import MasterEnabler

        enabler = MasterEnabler(app_config=mock_app_config)
        result = enabler.get()

        assert result == {"status": "true"}

    @patch(PIHOLE_CLIENT_PATCH)
    def test_alldns_enable(self, mock_client_class, mock_app_config, mock_pihole_client):
        """Test enabling DNS blocking."""
        mock_client_class.return_value = mock_pihole_client
        mock_pihole_client.dns_control.get_blocking_status.return_value = {
            "blocking": "enabled",
            "timer": None,
        }

        from pihole.alldns import MasterEnabler

        enabler = MasterEnabler(app_config=mock_app_config)
        result = enabler.enable_dns_blocking()

        assert result == {"status": "true"}

    @patch(PIHOLE_CLIENT_PATCH)
    def test_alldns_disable(self, mock_client_class, mock_app_config, mock_pihole_client):
        """Test disabling DNS blocking."""
        mock_client_class.return_value = mock_pihole_client
        mock_pihole_client.dns_control.get_blocking_status.return_value = {
            "blocking": "disabled",
            "timer": 60,
        }

        from pihole.alldns import MasterEnabler

        enabler = MasterEnabler(app_config=mock_app_config)
        result = enabler.disable_dns_blocking(timer=60)

        assert result == {"status": "false"}


class TestUbiquitiRouter:
    """Test Ubiquiti router functions directly."""

    @patch("ubiquity.ubiquity.requests.session")
    def test_ubiquiti_init(self, mock_session, mock_app_config):
        """Test ubiquity.init creates UDM instance."""
        from ubiquity import ubiquity

        ubiquity.init(mock_app_config)

        assert ubiquity.udm is not None
        assert ubiquity.udm.controller == "192.168.1.1"

    @patch("ubiquity.ubiquity.requests.session")
    def test_ubiquiti_status_rule(
        self, mock_session_class, mock_app_config, mock_ubiquiti_session
    ):
        """Test getting rule status."""
        mock_session_class.return_value = mock_ubiquiti_session

        from ubiquity.ubiquity import UbiquitiOverlord

        overlord = UbiquitiOverlord(app_config=mock_app_config)
        overlord.first_connect()
        overlord.parse_firewall_rules()

        result = overlord.status_rule("Block_Gaming")

        assert result == {"status": True}

    @patch("ubiquity.ubiquity.requests.session")
    def test_ubiquiti_change_rule(
        self, mock_session_class, mock_app_config, mock_ubiquiti_session
    ):
        """Test changing rule status."""
        mock_session_class.return_value = mock_ubiquiti_session

        from ubiquity.ubiquity import UbiquitiOverlord

        overlord = UbiquitiOverlord(app_config=mock_app_config)
        overlord.first_connect()
        overlord.parse_firewall_rules()

        result = overlord.change_rule("enabled", "Block_Gaming")

        assert "status" in result

    @patch("ubiquity.ubiquity.requests.session")
    def test_ubiquiti_change_device(
        self, mock_session_class, mock_app_config, mock_ubiquiti_session
    ):
        """Test blocking/unblocking device."""
        mock_session_class.return_value = mock_ubiquiti_session

        from ubiquity.ubiquity import UbiquitiOverlord

        overlord = UbiquitiOverlord(app_config=mock_app_config)
        overlord.first_connect()

        result = overlord.change_device("offline", "kids_devices")

        assert result == {"status": "offline"}


@pytest.fixture
def configured_controller(tmp_path, monkeypatch):
    """Run the real app/lifespan against an isolated configuration file."""
    import controller

    config_file = tmp_path / "config.ini"
    load_config = controller.init_config
    monkeypatch.setattr(
        controller, "init_config", lambda app, *args: load_config(app, str(config_file))
    )
    routes = controller.app.router.routes[:]
    lifespan = controller.app.router.lifespan_context
    yield controller.app, config_file
    controller.app.router.routes[:] = routes
    controller.app.router.lifespan_context = lifespan
    controller.app.openapi_schema = None


class TestControllerConfig:
    def test_omitted_flags_disable_subsystems(self, configured_controller):
        app, config_file = configured_controller
        config_file.write_text("[general]\n")
        with TestClient(app) as client:
            assert client.get("/").json() == {"status": "alive"}
            assert set(client.get("/openapi.json").json()["paths"]) == {"/"}

    def test_config_lists_and_environment_precedence(self, tmp_path, monkeypatch):
        import controller

        monkeypatch.setenv("REMOTE_PI_LIST", "pi-one.test  \t pi-two.test")
        monkeypatch.setenv("REMOTE_PI_PASSWORD", "test-password")
        monkeypatch.setenv("REMOTE_UBIQUITI_DEVICE", "unifi.test")
        monkeypatch.setenv("REMOTE_UBIQUITI_API_KEY", "test-key")
        monkeypatch.setenv("MQTT_BROKER", "ignored.test")
        monkeypatch.setenv("MQTT_PORT", "1884")
        config_file = tmp_path / "config.ini"
        config_file.write_text("""[general]
pihole_control_enabled = yes
ubiquiti_control_enabled = true
mqtt_announce_enabled = 1
[allow_domains]
school =
    school.example.test

    login.example.test
[block_domains]
video = video.example.test
[ubiquiti]
[ubiquiti_targets]
kids =
    AA:BB:CC:DD:EE:FF
[ubiquiti_rules]
rules =
    Allow School

    Allow Video
[mqtt]
broker = configured.test
lwt_topics =
    stat/controller/one

    stat/controller/two
""")
        config = controller.init_config(None, str(config_file))
        assert config["remote_pi_list"] == ["pi-one.test", "pi-two.test"]
        assert config["remote_pi_password"] == "test-password"
        assert config["allow_domains"]["school"] == [
            "school.example.test", "login.example.test"
        ]
        assert config["ubiquiti_device"] == "unifi.test"
        assert config["ubiquiti_api_key"] == "test-key"
        assert config["ubiquiti_targets"] == {"kids": ["AA:BB:CC:DD:EE:FF"]}
        assert config["ubiquiti_rules"] == {"Allow School": {}, "Allow Video": {}}
        assert config["mqtt"] == {
            "broker": "configured.test", "port": 1884,
            "lwt_topics": ["stat/controller/one", "stat/controller/two"],
        }
        # An explicit INI value must win even over a malformed environment value.
        config_file.write_text(config_file.read_text() + "port = 1885\n")
        monkeypatch.setenv("MQTT_PORT", "invalid")
        assert controller.init_config(None, str(config_file))["mqtt"]["port"] == 1885

    @pytest.mark.parametrize("contents", [
        None,
        "[general]\npihole_control_enabled = maybe\n",
        "[general]\npihole_control_enabled = yes\n",
        "[general]\nmqtt_announce_enabled = yes\n",
        "[general]\nmqtt_announce_enabled = yes\n[mqtt]\nport = 70000\nlwt_topics = stat/test\n",
    ])
    def test_invalid_config_fails_startup(self, configured_controller, contents, monkeypatch):
        app, config_file = configured_controller
        for name in ("REMOTE_PI_LIST", "REMOTE_PI_PASSWORD"):
            monkeypatch.delenv(name, raising=False)
        if contents is not None:
            config_file.write_text(contents)
        with pytest.raises((OSError, ValueError, configparser.Error)):
            with TestClient(app):
                pytest.fail("Invalid configuration started the server")


class TestControllerLifespan:
    def test_restart_refreshes_routes_and_openapi(self, configured_controller):
        app, config_file = configured_controller
        # Empty groups need no upstream connections for unknown-name requests.
        enabled = """[general]
pihole_control_enabled = yes
ubiquiti_control_enabled = no
mqtt_announce_enabled = no
remote_pi_list = pi.test
remote_pi_password = test-password
[allow_domains]
[block_domains]
"""
        for contents, enabled_now in [(enabled, True), (enabled, True), ("[general]\n", False)]:
            config_file.write_text(contents)
            with TestClient(app) as client:
                response = client.get("/pihole/status/missing")
                assert response.status_code == (200 if enabled_now else 404)
                schema = client.get("/openapi.json").json()
                assert ("/pihole/status/{domain_block}" in schema["paths"]) == enabled_now
                assert response.json() == ({"status": "Unknown"} if enabled_now else {"detail": "Not Found"})

    @pytest.mark.parametrize("failure", ["shutdown-pihole", "shutdown-unifi", "startup"])
    def test_failure_still_closes_other_clients(
        self, configured_controller, mock_app_config, mock_pihole_client,
        mock_ubiquiti_session, monkeypatch, failure,
    ):
        import controller
        from copy import deepcopy

        app, _ = configured_controller
        monkeypatch.setattr(controller, "init_config", lambda *args: mock_app_config)
        domain_client = deepcopy(mock_pihole_client)
        dns_client = deepcopy(mock_pihole_client)
        domain_client.domain_management.get_domain.side_effect = lambda domain, *_: {
            "domains": [{"domain": domain, "enabled": True}]
        }
        domain_resource, dns_resource, unifi_resource = BytesIO(), BytesIO(), BytesIO()
        domain_client.close_session.side_effect = domain_resource.close
        dns_client.close_session.side_effect = dns_resource.close
        mock_ubiquiti_session.close.side_effect = unifi_resource.close
        clients = iter([domain_client, dns_client])
        monkeypatch.setattr(
            "pihole.base.PiHole6Client",
            lambda *args: next(clients),
        )
        monkeypatch.setattr("ubiquity.ubiquity.requests.session", lambda: mock_ubiquiti_session)
        if failure.startswith("shutdown"):
            def fail_close():
                failed_resource.close()
                raise RuntimeError("close failed")

            if failure == "shutdown-pihole":
                failed_resource = domain_resource
                domain_client.close_session.side_effect = fail_close
            else:
                failed_resource = unifi_resource
                mock_ubiquiti_session.close.side_effect = fail_close
        else:
            # Startup fails after the DNS clients are initialized/acquired.
            def fail_init(config):
                controller.pihole_router.pihole.get("youtube")
                controller.pihole_router.all_dns.get()
                raise RuntimeError("startup failed")

            monkeypatch.setattr(controller.ubiquity, "init", fail_init)
        with pytest.raises(RuntimeError, match="failed"):
            with TestClient(app) as client:
                assert client.get("/pihole/status/youtube").status_code == 200
                assert client.get("/alldns/").status_code == 200
                assert client.get("/ubiquiti/status_rule/Block_Gaming").status_code == 200
        assert dns_resource.closed
        assert domain_resource.closed
        if failure.startswith("shutdown"):
            assert unifi_resource.closed
