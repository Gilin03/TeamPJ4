# Flask 웹 스캔 및 Suricata-Wazuh 연동 설계

- 작성일: 2026-10-08
- 상태: 대화에서 추천 설계 승인됨. 구현 전 명세 검토 필요.
- 범위: 기존 Hydra 로그인 탐지는 보존하고, 웹 404 스캔과 Suricata 경보를 Wazuh에서 탐지·확인하며 검증된 신호만 제한 시간 차단한다.

## 목표와 완료 조건

1. Flask가 반환한 404 경로 탐색 신호를 Wazuh가 수집하고, 출발 IP별 반복 스캔을 경보로 만든다.
2. Kali WSL의 Suricata가 실습 대상 트래픽을 보고 Nmap 및 SQLmap 관련 경보를 eve.json에 기록한다.
3. Wazuh가 Suricata EVE JSON을 읽어 대시보드 경보를 만든다.
4. 높은 신뢰도의 지정 규칙만 Windows board-host Agent에서 제한 시간 방화벽 차단을 실행한다.
5. 정상 단건 404, 기존 Hydra 로그인 탐지, 기존 게시판 기능은 유지한다.

## 확인된 현재 상태

- Flask _web_scan_probe는 404 응답을 GELF의 web-scan 이벤트로 Graylog에 보낸다. Wazuh용 파일 이벤트는 기록하지 않는다.
- Flask의 security.log에는 로그인 실패가 기록되며, Windows Agent 설정은 security*.log만 수집한다.
- 현재 사용자 지정 디코더와 규칙은 로그인 실패 100230, 반복 실패 100231만 정의한다.
- Wazuh Manager에는 board-host Agent 001만 등록되어 있다. Kali WSL에는 Suricata 8.0.6이 설치되어 있으나 실행 중이 아니고 /var/log/suricata/eve.json은 비어 있으며 Wazuh Agent는 설치되어 있지 않다.
- Kali WSL에서 현재 Wazuh Manager 호스트 게이트웨이의 Agent 포트 1514와 등록 포트 1515는 TCP 연결 가능했다.
- 실행 중인 Manager의 전역 Active Response 블록은 주석 처리돼 있다. netsh.exe 명령 정의는 있지만 자동 차단 규칙은 활성화된 것으로 확인되지 않았다.
- TeamPJ4 저장소에는 .gitignore, 최상위 README.md, _9_Wazuh/docker-compose.yml, _9_graylog/docker-compose.yml의 기존 미커밋 변경이 있다. 이 설계 명세 외에는 해당 변경을 스테이징하거나 수정하지 않는다.

## 권장 데이터 흐름

### 공격 ②: 웹 404 스캔

1. Flask의 기존 404 처리 훅은 Graylog GELF 전송을 유지한다.
2. 같은 훅에서 별도 web_scan_404 보안 로그도 기존 security.log에 한 줄 기록한다.
3. 한 줄에는 타임스탬프, src_ip, 상태 코드 404, 정규화한 경로만 둔다. 쿼리 문자열, 쿠키, 본문, 인증값은 기록하지 않는다. 공백·개행·제어문자와 과도한 경로 길이를 정리해 로그 인젝션을 막는다.
4. 기존 Windows Agent가 감시하는 security*.log 경로를 재사용한다.
5. 사용자 지정 Wazuh 디코더가 src_ip, 상태 코드, 경로를 추출하고, 규칙은 단건 이벤트와 같은 출발 IP에서 60초 동안 5회 이상 발생한 반복 이벤트를 별도로 분류한다. 단건 404만으로 차단하지 않는다.

### 공격 ③: Suricata 탐지

1. Suricata 8.0.6을 Kali WSL의 eth0에서 실행하는 것을 우선안으로 한다.
2. Nmap·SQLmap 신호를 실제로 생성하는 Suricata 규칙 세트를 활성화하고, 먼저 해당 인터페이스가 대상 트래픽을 보고 경보를 기록하는지 확인한다. 제품명 문자열만으로 임의 탐지하지 않고 eve.json의 실제 서명·시그니처 ID를 기준으로 Wazuh 규칙을 만든다.
3. Kali에 Wazuh Agent를 설치·등록하고 /var/log/suricata/eve.json을 json 입력으로 수집한다. 공식 Wazuh Suricata 연동 방식은 Agent의 JSON 로그 수집을 사용한다.
4. Nmap 및 SQLmap 관련 이벤트를 Wazuh 대시보드에서 각각 식별할 수 있도록 서명에 근거한 사용자 지정 규칙을 구성한다.

### 제한 시간 차단

1. Wazuh Manager가 board-host Agent 001을 대상으로 Active Response를 실행할 수 있도록 defined-agent 위치를 사용한다. Suricata 이벤트가 Kali Agent에서 발생해도 실제 대상 호스트에서 차단을 수행한다.
2. 기존 Windows netsh.exe Active Response 명령을 우선 재사용한다. 실제 Agent에 실행 파일이 있는지, 추가 인자와 만료 취소가 동작하는지 구현 단계에서 확인한다.
3. 차단은 반복 404 및 검증된 고신뢰 Suricata 규칙에만 연결한다. 정상 단건 요청과 기존 Hydra 규칙은 변경하지 않는다.
4. 차단 시간은 300초로 시작한다. 만료 시 방화벽 규칙이 제거되는지 확인한다.
5. 실험 전에 서버·관리용 주소를 명시적으로 허용 목록에 넣는다. RFC1918 전체를 허용하지 않는다. 자동 차단을 켜기 전 Flask와 Suricata가 관측한 src_ip가 동일한 실제 Kali 출발 주소인지 확인한다.

Wazuh 문서상 defined-agent는 이벤트가 발생한 Agent와 다른 지정 Agent에서 Active Response를 실행할 수 있고, Windows에는 netsh.exe 차단 스크립트가 제공된다. Suricata 연동 문서는 Wazuh Agent가 /var/log/suricata/eve.json을 JSON 입력으로 읽는 구성을 안내한다.

## 검증 순서

1. Flask 테스트에서 404 한 건은 security.log와 Graylog에 모두 남고, 로그인 이벤트 형식 및 응답 코드는 바뀌지 않는지 확인한다.
2. Kali의 Suricata를 eth0에서 실행해 EVE 파일에 대상 연결과 관련한 실제 경보가 생기는지 확인한다. 경보가 없으면 Wazuh 규칙이나 차단을 먼저 만들지 않고 인터페이스·룰셋부터 진단한다.
3. Kali Agent가 EVE JSON을 Wazuh Manager로 전송하고, 실제 Suricata 이벤트가 Wazuh Dashboard의 Threat hunting / Events에 보이는지 확인한다.
4. 한 건의 404와 임계치 미만의 이벤트는 경보·차단하지 않고, 반복 임계치를 넘으면 지정 규칙의 경보가 발생하는지 확인한다.
5. 테스트용 Kali 출발 주소가 board-host 방화벽에서 제한 시간 차단되고 만료 뒤 제거되는지, Active Response 로그와 대시보드에서 확인한다.
6. 사용자가 이미 완료했다고 한 Hydra 실습의 기존 탐지·동작이 그대로 유지되는지 회귀 확인한다.

## 대안과 선택 이유

- 권장: 직접 Wazuh 수집. Flask 이벤트는 기존 Windows Agent 로그 경로로, Suricata EVE는 Kali Agent로 각각 Wazuh에 전달한다. 데이터 흐름이 짧고 각 신호의 출처를 추적하기 쉽다.
- Graylog 경유: Graylog 이벤트를 별도 전달기로 Wazuh에 다시 보내는 방법이다. 기존 GELF 경로를 재사용할 수 있지만 중계 구성과 필드 매핑이 추가되어 출처 추적이 복잡해진다.
- 별도 센서 VM/브리지: 더 넓은 네트워크를 감시할 수 있지만 WSL 대상 트래픽 미러링이 필요해 현재 실습에는 불필요하다.

## 위험 및 미확정 사항

- WSL의 eth0에서 실제 Hydra/Nmap/SQLmap 트래픽이 관측되는지는 아직 실험하지 않았다.
- Suricata Nmap·SQLmap 경보는 활성 규칙 세트와 패킷 가시성에 따라 달라진다. EVE 원본을 먼저 확인한 뒤 규칙 ID를 고정한다.
- Windows 방화벽 차단은 Kali의 게시판 접근을 일시 중지시킬 수 있다. 허용 목록, 만료, 수동 해제 절차를 준비하고 실습 대상에만 적용한다.
- board-host Agent ID 001이 재등록되어 바뀌면 defined-agent 설정을 새 ID와 대조한다.
- Manager Active Response는 현재 주석 상태다. 구현에서는 새 규칙 범위만 활성화하고, Hydra 로그인 규칙 및 기존 앱 차단 흐름은 별도 승인 없이 바꾸지 않는다.

## 공식 참고자료

- [Wazuh Suricata 연동](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html)
- [Wazuh Active Response 설정과 defined-agent](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html)
- [Wazuh Windows 기본 Active Response 스크립트](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/default-active-response-scripts.html)
