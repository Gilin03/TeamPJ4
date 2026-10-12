from datetime import timedelta

import pytest

from app import create_app
from extensions import db


@pytest.fixture
def client(tmp_path):
  logf = tmp_path / 'security.log'

  class TestConfig:
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'test.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'test-secret-key'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    SECURITY_API_KEY = 'test-security-key'
    ADMIN_API_KEY = 'test-admin-key'
    ADMIN_ALLOWLIST = []
    AUTO_POST_ON_DENY = False
    PUBLIC_API_KEY = None
    PUBLIC_API_URL = 'http://example.invalid/'
    SECURITY_LOG_PATH = str(logf)

  application = create_app(TestConfig)
  c = application.test_client()
  c._logf = logf
  yield c
  with application.app_context():
    db.session.remove()
    db.engine.dispose()


def read_log(client):
  return client._logf.read_text(encoding='utf-8') if client._logf.exists() else ''


def test_404_reaches_security_log_and_keeps_graylog(client, gelf_outbox):
  response = client.get(
      '/scanner/missing?should_not_log=fixture-secret',
      headers={'X-Forwarded-For': '203.0.113.91, 10.0.0.2'},
  )

  assert response.status_code == 404
  lines = read_log(client).splitlines()
  assert len(lines) == 1, lines
  assert 'web_scan_404' in lines[0]
  assert 'status=404' in lines[0]
  assert 'src_ip=203.0.113.91' in lines[0]
  assert 'path=/scanner/missing' in lines[0]
  assert 'should_not_log' not in lines[0]
  assert 'fixture-secret' not in lines[0]
  assert gelf_outbox, '기존 Graylog GELF web-scan 전송이 유지돼야 한다'
  assert b'web-scan' in gelf_outbox[-1][0]


def test_404_path_cannot_inject_extra_log_lines(client):
  response = client.get('/scanner/%0D%0Alogin_failed%20user=fake')

  assert response.status_code == 404
  assert len(read_log(client).splitlines()) == 1


def test_404_path_is_bounded(client):
  response = client.get('/' + 'a' * 240)

  assert response.status_code == 404
  line = read_log(client).splitlines()[0]
  assert len(line.split(' path=', 1)[1]) <= 200


def test_non_404_response_does_not_write_web_scan_event(client):
  response = client.get('/')

  assert response.status_code != 404
  assert read_log(client) == ''
