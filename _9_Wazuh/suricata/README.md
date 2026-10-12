# Wazuh scan detection for the lab

This setup observes scans against the Flask host through Wazuh. It keeps Hydra login rules 100230/100231 and Graylog GELF behavior unchanged.

## Flask 404 scan path

The board writes one `web_scan_404` line to its existing `logs/security.log`; the existing Windows Agent `security*.log` localfile collector is reused. Wazuh rule 100232 records a single 404. Rule 100233 correlates five events from the same source IP within 60 seconds and is the only 404 rule eligible for a 300-second Windows `netsh` Active Response.

## Suricata path

Kali WSL runs Suricata on `eth0` and writes EVE JSON to `/var/log/suricata/eve.json`. The Kali Wazuh Agent reads that file as JSON. The ET rules already present in the lab ruleset include Nmap NSE signature IDs 2009358/2009359 and SQLmap signature ID 2008538. Wazuh rules 100234 and 100235 map those signatures separately. Rule IDs are tied to observed signature IDs; if the active ruleset changes, re-check the EVE alert before changing them.

For this lab, Suricata HOME_NET is set to the current WSL default gateway (/32), which is the Windows Flask host. Re-check `ip route show default` after WSL networking changes and update HOME_NET before starting Suricata. Do not add the Kali source address to HOME_NET; ET's Nmap/SQLmap signatures expect an external source and a protected HTTP server.

## Install and configure Kali Agent

Use the official Wazuh 4.9.0 agent package compatible with the current Manager. Derive the manager address each time from the default route; do not commit it:

`GW=$(ip route show default | awk '{print $3}')`

Install/enroll the agent as `kali-suricata` using the current gateway on ports 1514/1515. Add the contents of `kali-agent-ossec-snippet.xml` to the Kali agent's `/var/ossec/etc/ossec.conf`, then start `wazuh-agent`. Keep `/var/log/suricata/eve.json` readable by the `wazuh` service account without making it world-writable.

## Safe verification

1. Run `sudo suricata -T -c /etc/suricata/suricata.yaml`; it must report successful configuration.
2. Start Suricata and confirm EVE JSON grows. Run a low-volume Nmap NSE HTTP title probe and a low-risk SQLmap baseline against only the owned Flask host.
3. Confirm EVE has the expected actual signature ID and source IP. If either scan is absent, diagnose interface visibility and HOME_NET before enabling Wazuh rules or firewall responses.
4. Confirm the Kali Agent is Active in Wazuh and Wazuh Events contains the EVE alert. Dashboard queries: `rule.id:100234` and `rule.id:100235`.
5. Confirm the observed Kali source address matches the Windows host's view before enabling any firewall response.

## Active Response

Wazuh Manager already defines the `netsh` command. Configure scoped `defined-agent` responses only for rules 100233, 100234, and 100235, target the currently verified board-host Agent ID, and set timeout to 300 seconds. Never target every agent. Keep explicit server/management addresses out of the test block list. Check `/var/ossec/logs/active-responses.log` and the Windows firewall rule before and after expiry; use the matching netsh delete action for immediate rollback.

## Current state record

This document describes the intended configuration. Update it with observed timestamps and results only after the run. No EVE alert or firewall response is claimed until verified live.
