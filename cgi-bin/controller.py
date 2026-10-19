#!/usr/bin/env python3

import urllib3
import sys
import os
import logging
import configparser
from fastapi import FastAPI
from contextlib import AsyncExitStack, asynccontextmanager

import aiomqtt

# Disable warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


sys.path.append(os.path.join(os.path.dirname(__file__), "../lib/"))

from pihole import pihole_router  # noqa: E402
from ubiquity import ubiquity  # noqa: E402

default_log_level = logging.INFO

logger = logging.getLogger()
logging.basicConfig(
    level=default_log_level,
    format="[%(asctime)s] - [%(name)s] - [%(funcName)s:%(lineno)d] - [%(levelname)s] - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
    force=True,
)

description = """
FastAPI to manage multiple Pi-holes DNS filtering and Ubiquiti network access controls. 🚀

## Key Features

### Pi-hole Management
*   **Domain-level Blocking/Allowing**: Dynamically enable or disable specific domain groups (e.g., regex blacklists or whitelists) on configured Pi-hole instances.
*   **Global DNS Control**: Enable or disable DNS blocking entirely across all connected Pi-hole devices, with an optional timer for temporary disabling.

### Ubiquiti Network Management
*   **Client Device Control**: Block or unblock individual client devices by their MAC address on the Ubiquiti Gateway.
*   **Firewall Rule Management**: Enable or disable custom firewall rules on the Ubiquiti Gateway to control network traffic.

## Compatibility Note

This API is designed for compatibility with Pi-hole v6 (utilizing `pihole6api`) and Ubiquiti Network devices (such as UniFi Dream Machine) through their respective APIs.
"""


def init_config(app, config_location: str = "../etc/config.ini"):
    """Load a complete configuration or fail before initializing any clients."""
    app_config = {"default_log_level": logging.DEBUG, "logger": logger}
    config = configparser.ConfigParser()
    with open(config_location) as config_file:
        config.read_file(config_file)
    if not config.has_section("general"):
        raise configparser.NoSectionError("general")

    def lines(section, option):
        return [line.strip() for line in config.get(section, option).splitlines() if line.strip()]

    def required(section, option, environment):
        value = config.get(section, option, fallback=os.environ.get(environment))
        if value is None or not value.strip():
            raise ValueError(f"Set [{section}] {option} or {environment}")
        return value

    for key in (
        "ubiquiti_control_enabled", "pihole_control_enabled", "mqtt_announce_enabled"
    ):
        try:
            app_config[key] = config.getboolean("general", key, fallback=False)
        except ValueError:
            raise ValueError(f"Invalid boolean for [general] {key}") from None

    if app_config["pihole_control_enabled"]:
        for area in ("allow_domains", "block_domains"):
            app_config[area] = {name: lines(area, name) for name in config.options(area)}
        app_config["remote_pi_list"] = required(
            "general", "remote_pi_list", "REMOTE_PI_LIST"
        ).split()
        # An explicitly empty password is valid for a Pi-hole without authentication.
        password = config.get(
            "general", "remote_pi_password", fallback=os.environ.get("REMOTE_PI_PASSWORD")
        )
        if password is None:
            raise ValueError("Set [general] remote_pi_password or REMOTE_PI_PASSWORD")
        app_config["remote_pi_password"] = password

    if app_config["ubiquiti_control_enabled"]:
        for field in ("DEVICE", "API_KEY"):
            key = f"ubiquiti_{field.lower()}"
            app_config[key] = required("ubiquiti", f"remote_{key}", f"REMOTE_UBIQUITI_{field}")
        app_config["ubiquiti_targets"] = {
            name: lines("ubiquiti_targets", name) for name in config.options("ubiquiti_targets")
        }
        app_config["ubiquiti_rules"] = {
            rule: {} for name in config.options("ubiquiti_rules")
            for rule in lines("ubiquiti_rules", name)
        }

    if app_config["mqtt_announce_enabled"]:
        mqtt = {
            "broker": config.get("mqtt", "broker", fallback=os.environ.get("MQTT_BROKER", "localhost")),
            "port": int(config.get("mqtt", "port", fallback=os.environ.get("MQTT_PORT", "1883"))),
            "lwt_topics": lines("mqtt", "lwt_topics"),
        }
        if not mqtt["broker"].strip() or not 1 <= mqtt["port"] <= 65535 or not mqtt["lwt_topics"]:
            raise ValueError("MQTT requires a broker, port in 1..65535, and nonempty lwt_topics")
        app_config["mqtt"] = mqtt
    return app_config


async def publish_to_mqtt(mqtt_config: dict, status: str):
    broker = mqtt_config.get("broker", "localhost")
    lwt_topics = mqtt_config.get("lwt_topics", [])
    port = mqtt_config.get("port", 1883)

    try:
        async with aiomqtt.Client(broker, port) as client:
            for topic in lwt_topics:
                logger.debug(f"Publishing LWT of '{status}' to '{topic}'...")
                await client.publish(topic, status, retain=True)
                logger.info(f"Published LWT of '{status}' to '{topic}'...")
    except aiomqtt.MqttError as e:
        logger.warning(f"MQTT publish failed (non-fatal): {e} for {lwt_topics}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    config_file = os.path.join(os.path.dirname(__file__), "../etc/", "config.ini")

    app_config = init_config(app, config_file)
    routes = app.router.routes[:]
    lifespan_context = app.router.lifespan_context
    app.openapi_schema = None
    try:
        async with AsyncExitStack() as cleanup:
            # Register first so the offline announcement runs after every client closes,
            # even when startup or another cleanup callback raises.
            if app_config["mqtt_announce_enabled"]:
                cleanup.push_async_callback(publish_to_mqtt, app_config["mqtt"], "false")
            if app_config["pihole_control_enabled"]:
                pihole_router.init(app_config)
                cleanup.callback(pihole_router.pihole.shutdown)
                cleanup.callback(pihole_router.all_dns.shutdown)
                app.include_router(pihole_router.main_router)
                app.include_router(pihole_router.alldns_router)
            if app_config["ubiquiti_control_enabled"]:
                ubiquity.init(app_config)
                cleanup.callback(ubiquity.udm.shutdown)
                app.include_router(ubiquity.router)
            if app_config["mqtt_announce_enabled"]:
                await publish_to_mqtt(app_config["mqtt"], "true")
            yield
    finally:
        # include_router also merges lifespan contexts. Restore both on restart,
        # including failed startup, and discard the schema for the old configuration.
        app.router.routes[:] = routes
        app.router.lifespan_context = lifespan_context
        app.openapi_schema = None


app = FastAPI(
    title="Overlord Network Kill Switch API",
    version="v2.6",
    openapi_version="3.0.2",
    description=description,
    summary="Ubiquity Gateway and PiHole DNS server management",
    terms_of_service="http://5l-labs.com/",
    contact={
        "name": "5L-Labs",
        "url": "https://github.com/5L-Labs/dns_admin",
        "email": "inquiry@5l-labs.com",
    },
    license_info={
        "name": "Apache 2.0",
        "identifier": "Apache",
    },
    lifespan=lifespan,
)


logger.info("starting the app...")


@app.get("/")
async def root():
    return {"status": "alive"}
