# Wazuh scan detection for the lab

This setup observes scans against the Flask host through Wazuh. It keeps Hydra login rules 100230/100231 and Graylog GELF behavior unchanged.

## Flask 404 scan path

The board writes a `web_scan_404` line to its existing `logs/security.log` and keeps sending the existing GELF event to Graylog. The tracked Wazuh decoder also accepts the instructor's `http_404` line format, so either spelling is collected by the same Windows Agent `security*.log` input. Rule 100232 records one 404; rule 100233 correlates five events from the same source IP within 60 seconds.

## Suricata paths

The Windows `board-host` agent watches TeamPJ4 `logs/security*.log`, including `security_suricata.log`. The maintained Kali forwarder is `forward_ids.py` in this folder. In Kali WSL it writes to `/mnt/c/ktb/team4/TeamPJ4/_7_board_test/logs/security_suricata.log`; a Windows `C:\ktb\...` path is not valid Linux path syntax. It reads `/tmp/ids/recovered/eve.json` by default, or the first path argument, sends GELF to Graylog UDP `12201`, writes timestamped `suricata_alert src_ip=... sid=... signature=...` lines, then exits at end of file. Start it after the test event is in EVE, or pass an EVE file containing that event. Wazuh rule `100250` matches the stable `suricata_alert` marker, rules `100251`/`100252` classify Nmap/SQLmap, and `100253` detects repeated alerts. This path does not require a separate Kali agent.

The EVE JSON path is retained as a second option: Kali WSL runs Suricata on `eth0`, and a separately enrolled Kali Wazuh Agent reads `/var/log/suricata/eve.json`. Rules 100234 and 100235 match the lab's observed ET Nmap NSE signature IDs 2009358/2009359 and SQLmap signature ID 2008538. The manager must show the Kali agent as Active before expecting events from this path.

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

This document describes the intended configuration. Update it with observed timestamps and results only after the run. On 2026-10-12, a controlled Nmap-format forwarder event produced Wazuh rule 100251 on agent 001 from `security_suricata.log`; this verifies the text-log forwarding path, not a live network scan. No firewall response is claimed.
