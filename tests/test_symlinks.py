"""Tests for skipping symlinks whose target lies outside the report directory."""

import logging
import os

import pytest
from test_sftp import make_uploader

# --------------------------------------------------------------------------
# symlinks pointing outside the local root
# --------------------------------------------------------------------------

symlinks = pytest.mark.skipif(not hasattr(os, 'symlink'), reason='requires symlinks')


def _uploaded_names(paramiko_stub):
    sftp = paramiko_stub._state['clients'][-1].sftp
    return sorted(os.path.basename(remote) for _local, remote in sftp.put_calls)


@symlinks
def test_symlink_inside_root_is_uploaded(paramiko_stub, tmp_path):
    root = tmp_path / 'reports'
    root.mkdir()
    (root / 'real.html').write_text('x')
    os.symlink(root / 'real.html', root / 'link.html')
    make_uploader(local_root=str(root), remote_root='/pub').run()
    assert _uploaded_names(paramiko_stub) == ['link.html', 'real.html']


@symlinks
@pytest.mark.parametrize('relative', [False, True])
def test_symlink_outside_root_is_skipped(paramiko_stub, tmp_path, caplog, relative):
    root = tmp_path / 'reports'
    root.mkdir()
    secret = tmp_path / 'weewx.conf'
    secret.write_text('password = hunter2')
    (root / 'index.html').write_text('x')
    target = os.path.join('..', 'weewx.conf') if relative else str(secret)
    os.symlink(target, root / 'leak.txt')

    up = make_uploader(local_root=str(root), remote_root='/pub')
    with caplog.at_level(logging.INFO):
        assert up.run() == 1
    assert _uploaded_names(paramiko_stub) == ['index.html']
    assert 'symlink target is outside' in caplog.text
    _ts, files = up.get_last_upload()
    assert str(root / 'leak.txt') not in files


@symlinks
def test_external_symlinks_can_be_allowed(paramiko_stub, tmp_path):
    root = tmp_path / 'reports'
    root.mkdir()
    shared = tmp_path / 'shared.css'
    shared.write_text('body {}')
    os.symlink(shared, root / 'shared.css')
    make_uploader(local_root=str(root), remote_root='/pub',
                  allow_external_symlinks='true').run()
    assert _uploaded_names(paramiko_stub) == ['shared.css']


@symlinks
def test_symlinked_local_root_is_supported(paramiko_stub, tmp_path):
    real_root = tmp_path / 'real'
    real_root.mkdir()
    (real_root / 'index.html').write_text('x')
    os.symlink(real_root, tmp_path / 'public_html')
    make_uploader(local_root=str(tmp_path / 'public_html'), remote_root='/pub').run()
    assert _uploaded_names(paramiko_stub) == ['index.html']
