# Kali Suricata 경보의 Wazuh 수집 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Kali WSL에서 관측 가능한 Nmap·SQLmap 실습 신호를 Suricata EVE JSON으로 기록하고 Kali Wazuh Agent가 Wazuh Manager로 전달해 대시보드에서 확인할 수 있게 한다. 검증된 신호만 board-host에서 300초 제한 차단한다.

**Architecture:** Suricata 8.0.6은 Kali WSL eth0에서 실행한다. 먼저 실제 패킷 가시성과 활성 룰셋을 검증하고, EVE JSON 파일을 읽는 Wazuh Agent 4.9.0을 설치·등록한다. 사용자 지정 Wazuh 규칙은 실제 캡처한 EVE 경보의 signature/signature_id에 근거해 만들며, 명확한 탐지 규칙만 Windows board-host Agent에 원격 Active Response를 요청한다.

**Tech Stack:** Kali WSL2, Suricata 8.0.6, suricata-update ET Open, Wazuh Manager 4.9.0, Wazuh Agent 4.9.0, EVE JSON, Wazuh XML rules, Windows netsh Active Response.

**Spec:** docs/superpowers/specs/2026-10-08-wazuh-web-scan-suricata-design.md

## Global Constraints

- Manager를 업그레이드하지 않는다. Kali Agent는 Manager와 호환되는 4.9.0으로 고정한다.
- Suricata가 실제로 관측하고 EVE에 기록한 signature/signature_id만 Wazuh 규칙 기준으로 사용한다. 근거 없이 시그니처 ID를 만들지 않는다.
- 패킷 가시성, Wazuh 수집, 출발 IP 일치가 확인되기 전에는 Active Response를 켜지 않는다.
- 고신뢰 Nmap/SQLmap 탐지만 board-host Agent에서 300초 제한 차단한다. 정상 트래픽 및 단순 단건 404는 차단하지 않는다.
- 서버·관리 주소만 개별 허용하고 RFC1918 전체를 허용하지 않는다. Kali WSL gateway 주소는 실행 시 동적으로 읽는다.
- 기존 Hydra/웹 스캔 설정과 미커밋 .gitignore, 최상위 README.md, _9_Wazuh/docker-compose.yml, _9_graylog/docker-compose.yml 변경은 수정·스테이징하지 않는다.
- EVE 로그는 보안 비밀·실사용 자격 증명이 들어가지 않도록 검토한다. 토큰·비밀번호를 시험 명령 인자나 출력으로 남기지 않는다.

## Review Focus

- eth0에서 대상 트래픽을 보지 못하면 탐지가 있는 것처럼 꾸미지 않는다. 검증: tcpdump/Suricata 통계와 EVE 경보를 비교하고, 패킷이 안 보이면 Active Response 단계로 진행하지 않는다.
- 룰셋에 Nmap/SQLmap 적용 시그니처가 없으면 ID를 추측하지 않는다. 검증: 활성 규칙·실제 테스트 EVE의 signature/signature_id를 함께 확인한다.
- SQLmap/Nmap 패턴은 정상 요청과 겹칠 수 있다. 검증: 낮은 위험의 정상 HTTP 요청·단순 TCP 연결이 차단 후보로 분류되지 않는다.
- WSL NAT 주소와 Windows Flask가 기록한 출발 IP가 다르면 방화벽 차단 대상을 오인할 수 있다. 검증: 동일 시험 흐름에서 EVE src_ip와 Flask/Wazuh srcip를 대조한다.
- EVE 권한·회전으로 Agent가 파일을 읽지 못할 수 있다. 검증: wazuh 계정으로 파일 읽기를 확인하고 회전 후 새 파일도 수집되는지 확인한다.

---

### Task 1: 센서 사전 확인과 Suricata 룰셋

**Files:**
- Create: _9_Wazuh/suricata/README.md
- Create: _9_Wazuh/suricata/kali-agent-ossec-snippet.xml
- No tracked change: Kali WSL Suricata runtime configuration and ruleset

**Interfaces:**
- Consumes: Kali WSL Suricata 8.0.6, eth0, live manager address from WSL default route.
- Produces: EVE alert records for actual controlled Nmap and SQLmap probes, each with observed signature, signature_id, src_ip, dest_ip.

- [ ] Step 1: Before edits, run ip route show default, suricata -T -c /etc/suricata/suricata.yaml, inspect active rules with suricata-update list-sources and read-only search. Save only sanitized EVE alert fields for test fixtures.
- [ ] Step 2: Run a low-volume Nmap service/version probe and SQLmap baseline against the user's own Flask test host only. Confirm traffic is visible on eth0 and each expected event is appended to /var/log/suricata/eve.json. If one signal is missing, diagnose interface and ruleset before creating any Wazuh match or block rule.
- [ ] Step 3: If ET Open is not enabled or has no applicable rule, update the source list and enable only et/open, then run suricata-update and suricata -T. Do not enable an unreviewed third-party ruleset. Repeat the controlled probes and record only observed EVE signature/signature_id.
- [ ] Step 4: Create README.md with the exact Kali commands, current route-derived manager endpoint procedure, successful EVE fields, and recovery commands. Create the XML localfile snippet that reads /var/log/suricata/eve.json with log_format json. Do not put a fixed WSL gateway in tracked files.

### Task 2: Kali Wazuh Agent JSON collection

**Files:**
- Modify at runtime only: Kali WSL /var/ossec/etc/ossec.conf
- Modify: _9_Wazuh/suricata/kali-agent-ossec-snippet.xml
- Reference: _9_Wazuh/suricata/README.md

**Interfaces:**
- Consumes: Task 1 EVE JSON path and dynamic WSL gateway.
- Produces: Wazuh Agent named kali-suricata delivering the raw EVE alert to Manager 4.9.0.

- [ ] Step 1: Read-only check apt-cache madison wazuh-agent; proceed only if the exact 4.9.0 package is available. Do not upgrade the Manager or install another major/minor line. If unavailable, stop and report before changing package sources or downloading packages.
- [ ] Step 2: Install the 4.9.0 agent, configure the Manager address from ip route show default at runtime, and enroll as kali-suricata through the already reachable 1515 enrollment port. Add the JSON localfile block from Task 1.
- [ ] Step 3: Ensure the Agent service account can read /var/log/suricata/eve.json without making the file world-readable. Verify as the wazuh account and after a Suricata log rotation.
- [ ] Step 4: Start the Agent and verify its status on Manager plus the EVE alert in Wazuh Events. Expected result: rule.groups:suricata or equivalent decoded Suricata fields appear and src_ip/signature agree with the EVE source.

### Task 3: Evidence-based Wazuh Nmap and SQLmap rules

**Files:**
- Create: _9_Wazuh/custom-rules/suricata-scan-rules.xml
- Create: _9_Wazuh/suricata/fixtures/suricata-nmap-alert.json
- Create: _9_Wazuh/suricata/fixtures/suricata-sqlmap-alert.json
- Modify: _9_Wazuh/suricata/README.md

**Interfaces:**
- Consumes: Task 2 decoded EVE events and the two actual observed signatures.
- Produces: Separate Wazuh alert rules for Nmap and SQLmap with documented source signatures and no secrets.

- [ ] Step 1: Build sanitized fixtures from the actual events, retaining the EVE JSON fields required by Wazuh and replacing source/destination IPs with TEST-NET addresses. Do not fabricate signature IDs.
- [ ] Step 2: Use wazuh-logtest to identify the installed 4.9 decoder fields. Add separate custom rules matching the observed alert.signature_id (and stable signature text only when needed). Use fresh local rule IDs in the existing custom range after checking for collisions.
- [ ] Step 3: Run wazuh-logtest on both positive fixtures and a benign event. Expected result: Nmap and SQLmap fixtures map to their own rules; benign HTTP/TCP events do not map to either scanner rule.
- [ ] Step 4: Deploy only validated XML to the Manager, run its configuration check, restart/reload the manager as required, then repeat live scans. Dashboard must show distinct Nmap and SQLmap alerts with the same src_ip/signature seen in EVE.

### Task 4: Restrict remote Active Response to validated rules

**Files:**
- Modify at runtime only: Wazuh Manager /var/ossec/etc/ossec.conf
- Modify at runtime only: Windows board-host Agent response configuration only if required
- Reference: _9_Wazuh/suricata/README.md

**Interfaces:**
- Consumes: Task 3 rule IDs, verified board-host Agent ID, EVE and Flask observed source IP.
- Produces: rule-specific remote response on board-host with timeout 300 seconds and expiry.

- [ ] Step 1: Reconfirm Wazuh Manager/Agent versions, board-host Agent ID, installed netsh add/delete support, the exact observed Kali source IP, and explicit server/management allowlist. Do not proceed if EVE and target-side source addresses disagree.
- [ ] Step 2: Back up the Manager runtime config. Add location=defined-agent targeting the verified board-host ID and timeout 300 only to high-confidence Nmap/SQLmap rules. Leave Hydra and web-scan response blocks untouched.
- [ ] Step 3: Verify Manager config, response start/delete events in Active Response logs, Windows firewall rule presence during the window, and cleanup after 300 seconds. A benign request and a normal port connection must remain unblocked.
- [ ] Step 4: Document manual recovery and verify no allowlist or credentials were committed.

### Task 5: End-to-end verification and handoff

**Files:**
- Reference: _9_Wazuh/suricata/README.md
- Reference: _9_Wazuh/custom-rules/suricata-scan-rules.xml

- [ ] Step 1: Repeat Suricata EVE, Agent ingestion, Wazuh rule match, dashboard, remote response, and timeout checks for each attack. Expected result: both attack types have traceable EVE→Wazuh events and only validated source addresses are temporarily blocked.
- [ ] Step 2: Confirm Hydra and 404 web-scan tests from the separate plan still work; do not change their rules as part of this plan.
- [ ] Step 3: Run suricata -T -c /etc/suricata/suricata.yaml, Manager config validation, wazuh-logtest fixtures, and cd _7_board_test; pytest -q. Record exact commands and actual outcomes in the runbook.
- [ ] Step 4: Show the source change list and secret scan results, stage only this plan's files, and commit separately. Do not stage pre-existing changes or claim runtime checks that were not executed.

## Official references

- Wazuh Suricata JSON integration: https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html
- Wazuh JSON decoder: https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html
- Wazuh defined-agent Active Response: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html
- Wazuh Windows Active Response scripts: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/default-active-response-scripts.html
- Wazuh 4.9 agent compatibility is checked against the currently installed 4.9.0 Manager before package installation.


