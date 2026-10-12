# Flask 404 스캔 탐지와 제한 시간 차단 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Flask의 반복 404 경로 탐색을 security.log → Wazuh 경보 → Windows board-host의 300초 Active Response 차단으로 연결하고, 단건 404와 Hydra 로그인을 그대로 유지한다.

**Architecture:** Flask는 기존 GELF 전송을 유지하면서 기존 Wazuh 감시 파일에 민감하지 않은 구조화 404 이벤트를 추가한다. 기존 Windows Agent가 security*.log를 계속 읽고, 새 사용자 규칙만으로 반복 이벤트를 탐지한다. Wazuh Manager의 Active Response는 반복 탐지 규칙 하나만 board-host Agent 001에서 실행한다.

**Tech Stack:** Flask 3, pytest, Wazuh Manager 4.9, Wazuh XML decoders/rules, Windows Agent Active Response (netsh).

**Spec:** docs/superpowers/specs/2026-10-08-wazuh-web-scan-suricata-design.md

## Global Constraints

- 기존 Hydra 로그인 규칙 100230/100231과 게시판·Graylog GELF 기능을 유지한다.
- 출발 IP 하나에서 60초 동안 5회 이상인 반복 404만 차단 후보로 만든다. 단건 404는 차단하지 않는다.
- Active Response 만료는 300초이며, 이벤트 발생 Agent와 다른 board-host Agent 001을 대상으로 한다.
- 실습 관리·서버 주소는 명시적으로 보호하고 RFC1918 전체를 허용 목록으로 처리하지 않는다.
- 기존 미커밋 .gitignore, 최상위 README.md, _9_Wazuh/docker-compose.yml, _9_graylog/docker-compose.yml 변경은 수정·스테이징하지 않는다.
- 비밀값, 요청 본문, 쿠키, 쿼리 문자열은 로그·문서·Git에 쓰지 않는다. Wazuh Manager 로컬 설정은 저장소의 compose 변경 없이 적용한다.

## Review Focus

- 404 경로의 개행·제어문자 또는 지나치게 긴 값은 로그 한 줄을 깨뜨리지 않고 길이 제한으로 정리한다. 테스트: 로그 인젝션 입력에도 이벤트가 정확히 한 줄이고 보안 값이 없다.
- 쿼리 문자열·본문·쿠키는 기록하지 않는다. 테스트: query에 임의 문자열을 넣은 404 요청 후 security.log에 경로만 있고 query 값은 없다.
- X-Forwarded-For에 여러 값이 있거나 비정상 공백이 있어도 기존 _client_ip() 정책의 첫 홉만 기록한다. 테스트: 다중 홉 헤더로 기록된 src_ip를 고정한다.
- 같은 IP 4회는 차단하지 않고 5회째만 반복 경보가 난다. 검증: wazuh-logtest에 동일 src_ip 이벤트를 순서대로 입력해 단건·4회·5회 경계를 확인한다.
- 관리·서버 주소 및 Hydra 신호는 새 차단 규칙의 부작용을 받지 않는다. 검증: 허용 주소 표와 기존 Hydra 로그인 테스트를 대조하고 AR 규칙이 100233에만 연결됐는지 확인한다.

---

### Task 1: Flask에서 안전한 404 보안 이벤트 기록

**Files:**
- Modify: _7_board_test/controllers/seclog.py
- Modify: _7_board_test/app.py
- Test: _7_board_test/tests/test_web_scan_signal.py

**Interfaces:**
- Consumes: 기존 _client_ip()와 controllers.gelf.send_gelf().
- Produces: write_web_scan_log(src_ip: str, status_code: int, path: str) -> None. security.log에 timestamp web_scan_404 status=404 src_ip=... path=... 한 줄을 기록하며 query/body/cookie를 포함하지 않는다.

- [ ] Step 1: test_web_scan_signal.py에 404 요청이 security.log에 한 줄을 추가하고 응답은 404인 실패 테스트를 쓴다. 같은 테스트에서 GELF outbox에도 기존 web-scan 이벤트가 남는지 확인한다.
- [ ] Step 2: pytest tests/test_web_scan_signal.py -q 를 실행한다. 예상 결과: 보안 파일 기록이 없어 실패한다.
- [ ] Step 3: seclog.py에 timestamp와 기존 _clean 정책을 재사용하는 write_web_scan_log를 추가한다. app.py의 _web_scan_probe에서 기존 GELF 전송을 유지하고 event 기록을 별도로 호출한다.
- [ ] Step 4: 로그 인젝션, 200자 초과 경로, query 비기록, 다중 X-Forwarded-For 첫 홉, 404 이외 응답의 무기록을 각각 테스트하고 pytest tests/test_web_scan_signal.py -q 와 pytest tests/test_login_success_signal.py tests/test_gelf_isolation.py -q 를 실행한다. 예상 결과: 모두 통과하고 기존 로그인 로그 형식이 동일하다.

### Task 2: Wazuh 디코더와 반복 404 규칙

**Files:**
- Create: _9_Wazuh/custom-rules/flask-webscan-decoder.xml
- Create: _9_Wazuh/custom-rules/flask-webscan-rules.xml
- Create: _9_Wazuh/docs/web-scan-active-response.md

**Interfaces:**
- Consumes: Task 1의 web_scan_404 한 줄 형식.
- Produces: base rule 100232와 repeated-scan rule 100233. 반복 규칙은 base rule 100232, 같은 src_ip, frequency 5, timeframe 60으로 한정한다.

- [ ] Step 1: 고정된 가상 IP와 경로만 포함하는 디코더 입력 샘플 및 기대 필드를 문서에 먼저 고정한다. wazuh-logtest에서 현재 규칙이 이를 아직 해석하지 못하는지 확인한다.
- [ ] Step 2: 두 XML 파일을 만든다. 단건 이벤트는 낮은 수준의 기록 경보만 만들고 반복 규칙만 별도 높은 수준으로 분류한다. Hydra 규칙 ID를 참조하거나 수정하지 않는다.
- [ ] Step 3: Wazuh Manager 컨테이너 안의 wazuh-logtest에 단건 이벤트와 동일 IP 4회/5회 시퀀스를 넣는다. 예상 결과: 1~4회에는 100233이 없고 5회 경계에서만 100233이 발생한다. 다른 src_ip 이벤트는 카운트를 섞지 않는다.
- [ ] Step 4: docker exec를 이용한 로그테스트 명령, rule ID, 예상 판정, 실패 시 원복 절차를 web-scan-active-response.md에 기록한다. 실제 Manager 설정을 바꾸기 전 XML 검사 결과가 통과해야 한다.

### Task 3: 반복 규칙에만 Windows Active Response 연결

**Files:**
- Modify at runtime only: Wazuh Manager의 /var/ossec/etc/ossec.conf 및 custom rules 디렉터리
- Modify at runtime only: Windows board-host Agent의 Active Response 설정(설치 상태가 요구할 때만)
- Reference: _9_Wazuh/docs/web-scan-active-response.md

**Interfaces:**
- Consumes: Task 2의 rule 100233, manager/agent의 현재 버전과 실제 Agent ID.
- Produces: board-host Agent에서 rule 100233에만 연결된 300초 IP 방화벽 차단 및 만료 해제.

- [ ] Step 1: 변경 전에 Manager/Agent 버전, Agent ID, netsh Active Response 스크립트 설치·삭제 동작, 현재 명시 허용 주소를 읽기 전용으로 확인한다. Agent ID가 001이 아니면 현재 ID를 사용한다. 불일치가 있으면 설정 변경 전에 사용자에게 보고한다.
- [ ] Step 2: 현재 런타임 설정 백업을 만든 뒤 custom rules와 scoped active-response 블록만 추가한다. location은 defined-agent, 대상은 확인된 board-host ID, timeout은 300초다. 기존 global 설정·Hydra rule·compose 파일은 수정하지 않는다.
- [ ] Step 3: Manager XML/config 검사를 실행하고 Agent 로그에서 시작·삭제 명령이 각각 확인되는지 검증한다. 예상 결과: custom rule 파싱 성공, 만료 후 차단 규칙 제거.
- [ ] Step 4: 허용 목록에 없는 실습용 테스트 출발 IP로 한 번 검증하고, 만료 전에 수동 복구 명령을 문서화한다. 실제 운영·관리 출발 IP는 차단 시험에 사용하지 않는다.

### Task 4: 회귀 검증과 저장

**Files:**
- Reference: _7_board_test/tests/test_web_scan_signal.py
- Reference: _9_Wazuh/docs/web-scan-active-response.md

- [ ] Step 1: cd _7_board_test; pytest -q 를 실행한다. 예상 결과: 전체 Flask 테스트 통과.
- [ ] Step 2: 로컬 승인된 실습 환경에서 단건 404와 5회 반복 스캔을 발생시켜 Wazuh Dashboard에서 100232/100233과 Active Response 기록을 확인한다. 단건은 경보 차단 없이 기록, 반복은 한시 차단, 만료 후 접근은 정상이어야 한다.
- [ ] Step 3: Hydra 로그인 실패 회귀를 확인해 기존 로그인 경보가 유지되고 404 규칙에 의해 영향받지 않는지 확인한다.
- [ ] Step 4: 저장소 변경 목록을 보여 주고 이 계획 관련 파일만 스테이징한다. 비밀값 검사 후 별도 커밋한다. bundle/테스트 결과나 실제 방화벽 시험을 실행하지 않았다면 미실행으로 기록한다.


