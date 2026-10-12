# TeamPJ4

Flask 게시판 기반 GitHub 조별 협업 실습 (`_7_board_test`)

- `_7_board_test/` : Flask 게시판 프로젝트 (실행 방법은 해당 폴더의 README 참고)
- `_7_board_test/{SH,TB,JH,HJ}/introduce.txt` : 조원별 자기소개 (본인 폴더만 수정)
- `_9_Wazuh/` : Wazuh docker-compose (실습 ①)
- `_9_graylog/` : Graylog docker-compose

## Local Wazuh configuration

Wazuh certificates and local configuration belong in `_9_Wazuh/config/`; this directory is ignored by Git and must not be committed. Graylog uses the explicit Docker network `9_graylog_default`, shared with the Wazuh Compose project. Start Graylog first, then Wazuh.
