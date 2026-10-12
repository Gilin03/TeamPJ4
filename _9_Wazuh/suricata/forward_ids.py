import json
import socket
import os
import re
import sys
from datetime import datetime

gw = "172.22.128.1"

# ── Wazuh 대시보드 집계용 텍스트 로그 (새로 추가) ──
# 에이전트가 읽는 호스트 파일. 한 줄 = "YYYY-MM-DD HH:MM:SS.mmm suricata_alert src_ip=.. sid=.. signature=.."
# 이 파일을 Wazuh 에이전트 localfile 로 등록하면 디코더(suricata-alert)+룰(100250~253)이 탐지해 wazuh-dashboard 에 뜬다.
WAZUH_LOG = "/mnt/c/ktb/team4/TeamPJ4/_7_board_test/logs/security_suricata.log"
EVE = sys.argv[1] if len(sys.argv) > 1 else "/tmp/ids/recovered/eve.json"

_UNSAFE = re.compile(r"[\r\n\t\x00-\x1f\x7f]+")   # 로그 인젝션 방지(개행·제어문자 → 공백)


def clean(v, limit=200):
    return _UNSAFE.sub(" ", str(v or "")).strip()[:limit] or "-"


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
os.makedirs(os.path.dirname(WAZUH_LOG), exist_ok=True)
wz = open(WAZUH_LOG, "a", encoding="utf-8")

with open(EVE, encoding="utf-8") as f:
    for line in f:
        event = json.loads(line)

        if event.get("event_type") != "alert":
            continue

        alert = event.get("alert", {})
        sig = alert.get("signature", "")

        # checksum, malformed packet 등 Suricata 자체 엔진 이벤트 제외
        if sig.startswith("SURICATA "):
            continue

        gelf = {
            "version": "1.1",
            "host": "suricata",
            "short_message": f"IDS: {sig}",
            "level": 4,
            "_rule": "ids-alert",
            "_src_ip": event.get("src_ip", ""),
            "_dst_ip": event.get("dest_ip", ""),
            "_signature": sig,
            "_category": alert.get("category", ""),
            "_sid": alert.get("signature_id", 0)
        }

        # ① Graylog GELF (기존 그대로)
        sock.sendto(
            json.dumps(gelf).encode("utf-8"),
            (gw, 12201)
        )

        # ② Wazuh 텍스트 한 줄 기록 (새로 추가 — 대시보드 집계용)
        now = datetime.now()
        ts = now.strftime("%Y-%m-%d %H:%M:%S.") + f"{now.microsecond // 1000:03d}"
        wz.write(
            f"{ts} suricata_alert "
            f"src_ip={clean(event.get('src_ip', ''), 45)} "
            f"sid={clean(alert.get('signature_id', 0), 15)} "
            f"signature={clean(sig)}\n"
        )
        wz.flush()

wz.close()
