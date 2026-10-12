# Flask 404 → Wazuh Active Response

The board writes `web_scan_404` to the existing `security.log`. The current Windows Agent already watches `security*.log`, so this does not alter the Hydra log path. Decoder `flask-board-webscan` extracts `srcip` and `url`; rules 100232/100233 classify single and repeated events. Rule 100233 requires five events from the same source IP in 60 seconds.

## Manager deployment and checks

Copy `flask-webscan-decoder.xml` to `/var/ossec/etc/decoders/` and `flask-webscan-rules.xml` to `/var/ossec/etc/rules/`. Back up the runtime `ossec.conf` before appending a new `<ossec_config>` section. The `netsh` command already exists in the Manager; add a scoped `<active-response>` for rule 100233 only, with `<location>defined-agent</location>`, the verified board-host agent ID, and `<timeout>300</timeout>`.

Use `/var/ossec/bin/wazuh-logtest` with this synthetic input (never a production IP):

`2026-10-08 00:00:00.000 web_scan_404 status=404 src_ip=198.51.100.20 path=/fixture-missing`

Expected: decoder `flask-board-webscan`, rule 100232. Feed five such lines within 60 seconds using the same synthetic IP; only then should rule 100233 match. Four lines and a different IP must not produce 100233.

Validate config before restarting Manager. Confirm rule 100233 reaches only the Windows board-host agent, block timeout is 300 seconds, the Active Response log records the start/delete actions, and access works again after expiry. For immediate rollback, remove the runtime block and invoke the matching netsh delete action. Do not change Hydra rules 100230/100231.
