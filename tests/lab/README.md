# Disposable MQTT network lab

The lab runs the real Mosquitto broker, repository Node-RED flows, FastAPI
controller, and Pi-hole v6, plus a small **stateful UniFi named-rule simulator**.
It uses fixed test credentials/configuration, not `etc/config.ini`, private
deployment files, or environment-provided home-network addresses. Published
ports bind only to loopback. The Node-RED editor is disabled.

```bash
.agents/setup             # In an Amp orb: install tools and locked dependencies
amp orb services ensure  # Supervised Docker daemon + persistent lab; API portal
scripts/lab check        # Exercise the running lab without removing it
```

Outside Amp, install Python 3.12, uv, OpenSSL, Docker Engine and Compose with
`up --wait` support, then run `scripts/lab test`. This builds the lab, waits for
health, runs automated cases and removes its containers/volumes even on failure.
CI runs the same command. Do not run `test` alongside the persistent orb lab:
stop `network-lab` first. Use `scripts/lab down` after an interrupted test.
The runner pins the Compose project to `overlord-lab`, ignoring
`COMPOSE_PROJECT_NAME`. Docker still uses your selected daemon/context; choose a
local development daemon, not a production one. For tests without services use
`make test-unit`; bare `pytest` intentionally collects integration cases too.

Local ports: MQTT 18883, API 19001, Pi-hole 18080, UniFi HTTPS 19443. In an orb,
use the API portal URL printed by `amp orb services ensure`, not a localhost URL.
No port is published for DNS or the Node-RED editor. The Docker bridge is not a
security isolation boundary; the safety boundary is disposable services with
fixed local destinations and no production credentials. Never attach home-network
configuration or secrets to this stack.
Preparation rejects unexpected broker/endpoint counts and leftover literal
non-lab HTTP URLs, IPv4 addresses or placeholders before writing the generated
flow. Update that validation deliberately when changing the exported flow layout.
This catches configuration drift; it is not a sandbox for arbitrary function-node
JavaScript or a substitute for outbound network isolation.

## Simulator contract and limits

- `GET /proxy/network/v2/api/site/default/firewall-policies` lists rules.
- `PUT .../firewall-policies/batch` accepts the client's single-rule ID/boolean update.
  This models the current client's request shape, not a verified UniFi API contract
  or general multi-rule batch semantics.
- `/__sim/state`, POST `/__sim/reset`, PUT `/__sim/rules` inspect/reset inventory.
- PUT `/__sim/fault/reject` rejects the next write with HTTP 503;
  `/__sim/fault/ignore` acknowledges it without applying it. Each fault is one-shot.
- Requests require `X-API-KEY: local-simulator-only`. The generated local TLS
  certificate is explicitly trusted by the controller; TLS verification stays on.

State is in memory, resettable, and single-process. Tests are serial and mutate
only this lab. The baseline restriction is deliberately absent from Overlord's
toggle configuration. Tests check MQTT confirmation against an independent
simulator state read, unrelated rules, retries, failed revokes and malformed
commands. Removed/duplicate names are covered by the route-level unit tests.
A failed revoke may leave an exception enabled. MQTT waits ignore retained
snapshots and tolerate older poll/echo values until the expected value arrives
within a deadline; independent device-state checks are still required.
DNS cases independently read the real Pi-hole API after MQTT commands: master
polarity, 300-second bypass, permanent timer clearing, timer-expiry feedback,
repeated commands, and repair of existing disabled domain entries.

This does **not** simulate UniFi packet filtering, VLAN admission, device identity,
application classification, real controller compatibility, or HomeKit itself.
Legacy device block/status APIs are not implemented by the simulator. See
[the policy guide](../../lib/ubiquity/POLICY.md) for required live acceptance tests.
Pi-hole starts with an empty gravity database seeded from its shipped schema;
the lab needs no external adlist downloads. One FastAPI worker makes test state
deterministic; it does not validate production multi-worker concurrency.

`.agents/setup` installs prerequisites only; `.amp/services.yaml` supervises
long-running processes. No resume hook is needed. After changing source or flows,
restart `network-lab` to regenerate local endpoints and rebuild. Generated flows,
TLS material and portal state are ignored by Git. Setup becomes available to new
project orbs only after these files reach the project's default branch.
