from datetime import datetime

from extensions import db


class BlockEvent(db.Model):
  """IP 차단/해제 이력 — 한 번 쌓이면 지우지 않는다(추가만 한다).

  blocked_ips 는 '지금 막혀 있는 IP' 만 담는다(해제하면 행이 사라진다).
  그래서 "언제, 누가, 왜 막았고 언제 풀었나" 는 이 표에 따로 쌓는다. 같은 IP 를
  여러 번 막고 풀어도 매번 한 줄씩 늘어난다.
  """
  __tablename__ = 'block_events'

  id = db.Column(db.Integer, primary_key=True)
  ip = db.Column(db.String(45), nullable=False, index=True)
  action = db.Column(db.String(10), nullable=False)     # 'block' | 'unblock'
  reason = db.Column(db.String(200))
  actor = db.Column(db.String(80))                      # 사람 아이디 | apikey
  source = db.Column(db.String(50))                     # ip-guard 등(n8n 이 보낸 값)
  created_at = db.Column(db.DateTime, default=datetime.now, index=True)

  def to_dict(self):
    return {
        'id': self.id, 'ip': self.ip, 'action': self.action,
        'reason': self.reason, 'actor': self.actor, 'source': self.source,
        'created_at': self.created_at.isoformat() if self.created_at else None,
    }
