# TeamPJ4 Wazuh 404 and Suricata Compatibility Plan

**Goal:** Make the tracked TeamPJ4 Wazuh configuration recognize both the instructor's HTTP 404 line and TeamPJ4's existing Suricata text alert lines, while keeping the current Suricata EVE JSON rules.

**Architecture:** Extend the tracked 404 decoder for both event spellings, add a decoder and rule IDs for the existing `security_suricata.log` text format, then mount these tracked files into the existing `wazuh-manager` container so the repository and runtime stay aligned.

**Tech Stack:** Wazuh 4.9 XML decoders/rules, Docker Compose.

**Spec:** Notion page `173-Suricata-HTTP404-Wazuh-1` supplied by the user; instructor reference commit `193e27e2061e882a4481f6112e337b1a1b99c7e8`.

## Global Constraints

- Keep the running manager name `wazuh-manager`; the instructor's latest rename to `wazuh-manager2` does not match this lab.
- Keep TeamPJ4's existing `web_scan_404` format and its Graylog GELF path.
- Preserve the existing Suricata EVE JSON rules and use unique IDs for text-log rules.
- Collect TeamPJ4 `logs/security*.log` through the existing `flask-board` Windows agent group.

## Review Focus

- Both `http_404` and `web_scan_404` lines decode to Wazuh rule 100232.
- Millisecond timestamps and trailing Windows line endings do not prevent decoding.
- Existing EVE JSON rules remain intact and text-rule IDs do not collide.
- Docker Compose mounts source files to the matching manager paths.
- `agent.conf` points only at the active TeamPJ4 log/template paths.

## Tasks

### Task 1: Tracked decoders and rules

- Update `_9_Wazuh/custom-rules/flask-webscan-decoder.xml` to accept both 404 prefixes.
- Add `_9_Wazuh/custom-rules/suricata-text-decoder.xml` for timestamped `suricata_alert src_ip=... sid=... signature=...` lines.
- Extend `_9_Wazuh/custom-rules/suricata-scan-rules.xml` with unique text-alert, Nmap, SQLmap, and same-source frequency rules while preserving EVE JSON rules.
- Verify with Wazuh `wazuh-logtest` for both 404 forms and representative Suricata text lines.

### Task 2: Runtime alignment

- Add read-only Docker Compose mounts for the TeamPJ4 agent group config and tracked decoder/rule files.
- Recreate only the Wazuh manager service, validate its config, then verify the board-host agent and dashboard events.

**Ruling:** Work in the existing `태빈-연습장` checkout because the user explicitly requires changes to be visible in `C:\ktb\team4\TeamPJ4`; the checkout is clean and is not `main`/`master`. Cost if wrong: changes are made directly on the user's active branch.
