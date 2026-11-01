"""Tests for the Terrapin (CVE-2023-48795) paramiko version warning."""

import logging
import types

import pytest
from test_sftp import make_uploader

import user.sftp as sftp_module
from user.sftp import check_paramiko_version, is_terrapin_vulnerable, paramiko_version

# --------------------------------------------------------------------------
# paramiko version check (Terrapin, CVE-2023-48795)
# --------------------------------------------------------------------------

@pytest.mark.parametrize('attrs, expected', [
    ({'__version_info__': (3, 5, 1), '__version__': '3.5.1'}, (3, 5, 1, 1)),
    ({'__version__': '3.3.1'}, (3, 3, 1, 1)),
    ({'__version__': '4.0'}, (4, 0, 0, 1)),
    ({'__version__': '3.4.0rc1'}, (3, 4, 0, 0)),
    ({'__version__': '3.4.0.dev1'}, (3, 4, 0, 0)),
    ({'__version__': '3.4.0b2'}, (3, 4, 0, 0)),
    ({'__version__': '3.4.0.post1'}, (3, 4, 0, 1)),
    ({'__version__': '3.4.0+deb12u1'}, (3, 4, 0, 1)),
    ({'__version_info__': (2, 9, 2)}, (2, 9, 2, 1)),
    ({'__version__': 'unknown'}, None),
    ({}, None),
])
def test_paramiko_version_parsing(attrs, expected):
    assert paramiko_version(types.SimpleNamespace(**attrs)) == expected


@pytest.mark.parametrize('version, vulnerable', [
    ('2.4.3', False),      # before ETM MACs were added
    ('2.5.0rc1', True),    # pre-release of the first affected version
    ('2.5.0', True),
    ('2.12.0', True),
    ('3.3.1', True),
    ('3.4.0rc1', True),    # pre-release is not the patched release
    ('3.4.0.dev1', True),
    ('3.4.0', False),
    ('3.4.0.post1', False),
    ('3.5.1', False),
    ('5.0.0', False),
    ('unknown', False),
])
def test_affected_range(version, vulnerable):
    parsed = paramiko_version(types.SimpleNamespace(__version__=version))
    assert is_terrapin_vulnerable(parsed) is vulnerable


@pytest.fixture
def fresh_version_check(monkeypatch):
    monkeypatch.setattr(sftp_module, '_paramiko_version_checked', False)


def test_old_paramiko_warns_once(fresh_version_check, caplog):
    old = types.SimpleNamespace(__version__='3.3.1')
    with caplog.at_level(logging.WARNING):
        check_paramiko_version(old)
        check_paramiko_version(old)
    assert caplog.text.count('CVE-2023-48795') == 1
    assert '3.3.1' in caplog.text and '3.4.0' in caplog.text


def test_prerelease_of_fixed_version_warns(fresh_version_check, caplog):
    with caplog.at_level(logging.WARNING):
        check_paramiko_version(types.SimpleNamespace(__version__='3.4.0rc1'))
    assert 'paramiko 3.4.0rc1 is vulnerable' in caplog.text


@pytest.mark.parametrize('version', ['2.4.3', '3.4.0', '3.5.1', '5.0.0', 'unknown'])
def test_safe_unaffected_or_unknown_paramiko_does_not_warn(fresh_version_check, caplog,
                                                            version):
    with caplog.at_level(logging.WARNING):
        check_paramiko_version(types.SimpleNamespace(__version__=version))
    assert 'CVE-2023-48795' not in caplog.text


def test_run_checks_paramiko_version(fresh_version_check, paramiko_stub, tmp_path,
                                     monkeypatch, caplog):
    monkeypatch.setattr(paramiko_stub, '__version__', '2.12.0', raising=False)
    with caplog.at_level(logging.WARNING):
        make_uploader(local_root=str(tmp_path)).run()
    assert 'CVE-2023-48795' in caplog.text
