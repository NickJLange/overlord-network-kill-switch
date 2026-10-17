# Restricted-default UniFi access (opt-in, not deployed)

Overlord can toggle **existing named firewall policies**. It does not create or
reorder policies, assign VLANs, enroll devices, or verify effective traffic
permissions. The current MAC `block-sta` / `unblock-sta` controls remain legacy
controls; inverting those commands does not implement an allowlist.

## Put the default restriction on a network boundary

All ordinary clients, including new and randomized MAC addresses, must enter a
restricted network/VLAN. Apply the default restriction to that entire network,
not to a list of known clients. Define approved exceptions separately. A new MAC
must never cause a client to fall into an unrestricted fallback network.

Choose the admission boundary before configuring exceptions:

- Separate SSIDs/VLANs with distinct credentials, or PPSK passwords mapped to
  VLANs, can keep restrictions independent of MAC changes. Anyone possessing an
  approved password has that VLAN's access: this is credential-based access, not
  proof of a particular physical device. PPSK is WPA2-only, not 6 GHz.
- WPA2/WPA3 Enterprise with credential-based RADIUS VLAN assignment can provide
  individual enrollment; use device certificates where supported if stronger
  device binding is required. MAC-based RADIUS authentication is still MAC-based.
- A source MAC/device selector is only a weaker convenience exception. A changed
  MAC loses that exception and must fall back to the network restriction. A
  spoofed approved MAC may inherit it. Do not call this spoof-resistant identity.

Secure wired port VLAN assignments, trunk access, other SSIDs, VPN ingress and
inter-VLAN paths as well. A client able to join an unrestricted network can bypass
the restricted network's rules. Unknown credentials should be denied admission or
assigned only to a restricted network, never an approved one.

## Rule intent and precedence

For the relevant source-zone → External pair, use narrow ALLOW exceptions ahead
of the baseline restriction, and keep that restriction ahead of any matching
built-in or custom broad allow. Preserve necessary invalid-traffic protections.
UniFi documents that new custom policies precede built-ins but follow existing
custom policies; use **Reorder** to inspect the actual result. Configuration-file
line order does not control UniFi precedence.

Example intent, **not an importable policy or a description of your live rules**:

| Priority among these rules | Source | Destination | Action | Overlord switch |
| --- | --- | --- | --- | --- |
| 1 | Explicitly approved membership | YouTube app traffic, External | Allow | `Allow_YouTube_Approved` |
| 2 | Explicitly approved broader-access membership | External | Allow | `Allow_Internet_Approved` |
| 3 | Every restricted network, including approved members | Required baseline restrictions, External | Block | Never toggle |

The broader-access exception overrides the YouTube restriction too. Turning OFF
YouTube alone cannot revoke access while the broader exception remains ON.
Choose whether the baseline blocks just entertainment applications or **all**
Internet traffic except explicit essential-service permits; that decision is not
encoded in this repository. A broad allow must not accidentally override other
security restrictions: scope it and place independent security denies accordingly.

Review IPv4 **and** IPv6, TCP/UDP (including QUIC), return traffic, connection-state
rules and schedules. A rule's `enabled` flag is not its effective traffic state.
Established flows may outlive a change. Application classification, DNS filtering,
VPNs and proxies require actual client tests; an application allow is not a promise
to defeat every bypass. A UniFi allow does not override Pi-hole DNS blocking.
Keep DNS/DHCP and management connectivity outside blanket Internet denies.

## Opt in after operator review

1. Obtain approval for live changes and retain an out-of-band management path.
2. Confirm the inputs below. Create the baseline and disabled exceptions in UniFi,
   verify source membership and precedence, and test with a non-critical client.
   Keep existing controls until the replacement has been verified; retire old
   conflicting rules and automations deliberately, not by blindly inverting them.
3. In `[ubiquiti_rules]`, replace the relevant legacy names with exact, unique
   exception names. Exclude the baseline deny from Overlord's configurable rule
   list so these endpoints cannot disable it. Keep unrelated controls only where
   they cannot undo the baseline. No special section or new API is needed:

   ```ini
   [ubiquiti_rules]
   rules: Allow_YouTube_Approved
          Allow_Internet_Approved
   ```

4. Point access switches at those rule names, not `change_device` MAC targets:
   `cmnd/router_controller/change_rule/Allow_YouTube_Approved`, payload `true` to
   enable the ALLOW or `false` to disable it. Feedback is
   `stat/router_controller/status_rule/Allow_YouTube_Approved`. Use ON = access
   granted; remove any old HomeKit inversion used for a BLOCK rule. The existing
   `/ubiquiti/enable_rule/{target}` and `/disable_rule/{target}` endpoints keep
   their rule-enabled meaning for all legacy rules too.
5. Keep Overlord/MQTT/Node-RED administrative access inaccessible to restricted
   clients. The service itself does not authenticate these control endpoints.

Writes resolve the rule name against a fresh controller read. Missing or duplicate
configured names are rejected, and failed refreshes discard old rule data. Only
the selected rule's ID and `enabled` flag are sent. A successful HTTP write alone
is not confirmation: the rule must read back with the requested state. Failures
return an error or `status: "unknown"`, never an invented success. Node-RED does
not publish an ON/OFF confirmation for those failures and raises a node error
(wire a Catch node to your operator alerting). Repeated rule commands are not
deduplicated, so an operator can retry after checking state.

An unsuccessful revoke may leave access **enabled**; no rollback or fail-closed
network guarantee is possible after a timeout. Read back from UniFi, investigate,
then retry. Status reads can use a cache for up to 60 seconds. Multiple workers,
other administrators and concurrent commands can change state after confirmation.
Unique names are configuration selectors, not immutable authorization identities:
a same-name replacement or an edited source/action must be reviewed in UniFi.

## Inputs still required before live migration

- Gateway model/firmware, Network version, site (this integration targets
  `default`), and whether policies are zone-based or legacy traffic rules.
- SSID/PPSK/RADIUS and wired-port → VLAN → zone mappings, unknown-client fallback,
  and which credentials/ports restricted users can access. Do not send passwords.
- Redacted policy export or screenshots showing IDs, unique names, order,
  enabled/action, source membership, destination/apps, IP versions, connection
  states and schedules, including broad allows, app blocks and DNS policies.
- Approved members for YouTube versus broader access, chosen admission/identity
  boundary, required baseline services and whether the baseline is entertainment
  blocking or a full Internet deny.
- Current MQTT/HomeKit topic mappings and switch inversions; independent Pi-hole
  restrictions; management/recovery access for a supervised test.

## Required network acceptance tests (not verified by mocked unit tests)

| Scenario | Required observation |
| --- | --- |
| Unknown client or unapproved client rotating MAC/IP | Restricted baseline still applies on IPv4 and IPv6 |
| MAC-scoped approved client rotates MAC | Exception lost; no automatic promotion of new identity |
| Credential-enrolled client rotates MAC | Same assigned VLAN policy; no escape into an unrestricted fallback |
| Unapproved client spoofs an approved MAC | Must not gain access if credential-bound identity is required; MAC-only exceptions cannot guarantee this |
| Only YouTube exception ON | Intended members get YouTube, others do not; unrelated baseline restrictions remain |
| Broader exception ON | Only intended members get broader access; YouTube OFF alone does not revoke it |
| Both exceptions OFF | All relevant members return to baseline; test new and existing streams |
| Controller unreachable, rejected update, failed readback | No switch-success confirmation; inspect actual policy, especially after failed revoke |
| Restart of Overlord/Node-RED | Baseline persists in UniFi; no automatic access promotion |

Local tests cover the rule-control and message contracts, **not** device admission,
firewall evaluation or encrypted traffic classification. No live network changes
are performed by this guide or the test suite.

## Authoritative references

- [UniFi zone-based firewall, precedence, IPv4/IPv6 and return traffic](https://help.ui.com/hc/en-us/articles/115003173168-Zone-Based-Firewalls-in-UniFi)
- [Application filtering and zone-based policies](https://help.ui.com/hc/en-us/articles/28314415752727-Application-Filtering-in-UniFi)
- [PPSK and credential-based RADIUS VLAN assignment](https://help.ui.com/hc/en-us/articles/29887064407319-Using-PPSK-RADIUS-for-Multiple-VLANs-On-an-SSID-in-UniFi-Network)
- [MAC allowlists and randomization caveat](https://help.ui.com/hc/en-us/articles/18565355579799-MAC-Address-Restricting)
- [MAC-based RADIUS credentials](https://help.ui.com/hc/en-us/articles/115004589707-MAC-Based-VLAN-Assignment-Using-802-1x-in-UniFi-Network)
