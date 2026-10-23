"""Tests for password_env / private_key_pass_env."""

import logging

import pytest
from test_sftp import _generator

from user.sftp import get_secret

# --------------------------------------------------------------------------
# secrets from environment variables
# --------------------------------------------------------------------------

def test_get_secret_inline_value():
    assert get_secret({'password': 'inline'}, 'password') == 'inline'
    assert get_secret({}, 'password') is None


def test_get_secret_from_environment(monkeypatch):
    monkeypatch.setenv('WEEWX_SFTP_PASSWORD', 'from-env')
    skin = {'password_env': 'WEEWX_SFTP_PASSWORD'}
    assert get_secret(skin, 'password') == 'from-env'


@pytest.mark.parametrize('env_value', [None, ''])
def test_get_secret_missing_or_empty_variable_rejected(monkeypatch, env_value):
    if env_value is None:
        monkeypatch.delenv('WEEWX_SFTP_PASSWORD', raising=False)
    else:
        monkeypatch.setenv('WEEWX_SFTP_PASSWORD', env_value)
    with pytest.raises(ValueError, match='WEEWX_SFTP_PASSWORD'):
        get_secret({'password_env': 'WEEWX_SFTP_PASSWORD'}, 'password')


def test_get_secret_both_forms_rejected(monkeypatch):
    monkeypatch.setenv('WEEWX_SFTP_PASSWORD', 'from-env')
    skin = {'password': 'inline', 'password_env': 'WEEWX_SFTP_PASSWORD'}
    with pytest.raises(ValueError, match='not both'):
        get_secret(skin, 'password')


def test_generator_passes_secrets_from_environment(tmp_path, monkeypatch):
    calls = {}

    class FakeUploader:
        def __init__(self, **kwargs):
            calls.update(kwargs)

        def run(self):
            return 0

    monkeypatch.setattr('user.sftp.SFTPUploader', FakeUploader)
    monkeypatch.setenv('SFTP_PW', 'pw-from-env')
    monkeypatch.setenv('SFTP_KEY_PASS', 'pass-from-env')
    skin = {
        'server': 'h', 'user': 'u', 'path': '/pub',
        'password_env': 'SFTP_PW',
        'private_key': '/k', 'private_key_pass_env': 'SFTP_KEY_PASS',
    }
    gen = _generator(tmp_path, skin)
    gen.run()
    assert gen.success is True
    assert calls['password'] == 'pw-from-env'
    assert calls['private_key_pass'] == 'pass-from-env'


def test_generator_missing_secret_variable_fails_without_leaking(tmp_path, monkeypatch, caplog):
    monkeypatch.delenv('SFTP_PW', raising=False)
    skin = {'server': 'h', 'user': 'u', 'path': '/pub', 'password_env': 'SFTP_PW'}
    gen = _generator(tmp_path, skin)
    with caplog.at_level(logging.ERROR):
        gen.run()
    assert gen.success is False
    assert 'SFTP_PW' in caplog.text
