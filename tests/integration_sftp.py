"""Real SSH/SFTP integration checks, run separately from pytest's Paramiko fake.

Only loopback sockets and generated temporary credentials/files are used.
"""
import contextlib
import errno
import io
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from user.sftp import SFTPUploader  # noqa: E402


def generate_key():
    raw = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption())
    return raw, paramiko.Ed25519Key.from_private_key(io.StringIO(raw.decode()))


class RootedSFTP(paramiko.SFTPServerInterface):
    def __init__(self, server, *args, root, stop, stalled, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.root = root
        self.stop = stop
        self.stalled = stalled

    def path(self, remote):
        local = (self.root / remote.lstrip('/')).resolve()
        if not local.is_relative_to(self.root):
            raise PermissionError(errno.EACCES, 'outside fixture root')
        return local

    def stat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(self.path(path).stat())
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)

    def mkdir(self, path, attr):
        try:
            self.path(path).mkdir()
            return paramiko.SFTP_OK
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)

    def open(self, path, flags, attr):
        if self.stalled and path.endswith('blocked.html'):
            self.stop.wait(5)
        try:
            descriptor = os.open(self.path(path), flags, 0o600)
            mode = 'r+b' if flags & os.O_RDWR else 'wb' if flags & os.O_WRONLY else 'rb'
            stream = os.fdopen(descriptor, mode)
            handle = paramiko.SFTPHandle(flags)
            handle.readfile = stream
            handle.writefile = stream
            return handle
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)


@contextlib.contextmanager
def server(root, silent=False, stalled=False):
    host_raw, host_key = generate_key()
    client_raw, client_key = generate_key()
    stop = threading.Event()
    transports = []
    workers = []
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(5)
    listener.settimeout(0.1)
    port = listener.getsockname()[1]
    known_hosts = root / 'known_hosts'
    known_hosts.write_text('[127.0.0.1]:%s %s %s\n' %
                          (port, host_key.get_name(), host_key.get_base64()))
    private_key = root / 'client_key'
    private_key.write_bytes(client_raw)
    private_key.chmod(0o600)

    class Authentication(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            return (paramiko.AUTH_SUCCESSFUL if username == 'alice' and password == 'fixture'
                    else paramiko.AUTH_FAILED)

        def check_auth_publickey(self, username, key):
            return (paramiko.AUTH_SUCCESSFUL if username == 'alice' and key == client_key
                    else paramiko.AUTH_FAILED)

        def get_allowed_auths(self, username):
            return 'publickey,password'

        def check_channel_request(self, kind, chanid):
            return (paramiko.OPEN_SUCCEEDED if kind == 'session'
                    else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

        def check_channel_subsystem_request(self, channel, name):
            if silent:
                return True  # Authenticate, then never send an SFTP version.
            return super().check_channel_subsystem_request(channel, name)

    def serve(connection):
        transport = paramiko.Transport(connection)
        transports.append(transport)
        transport.add_server_key(host_key)
        transport.set_subsystem_handler('sftp', paramiko.SFTPServer, RootedSFTP,
                                        root=root, stop=stop, stalled=stalled)
        try:
            transport.start_server(server=Authentication())
            while transport.is_active() and not stop.wait(0.1):
                pass
        except (paramiko.SSHException, EOFError, OSError):
            # Rejected host keys and timeout tests intentionally close sockets
            # while the server may still be negotiating.
            pass
        finally:
            transport.close()

    def accept():
        while not stop.is_set():
            try:
                connection, _address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(target=serve, args=(connection,), daemon=True)
            workers.append(worker)
            worker.start()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        yield {'server': '127.0.0.1', 'port': port, 'user': 'alice',
               'password': None, 'private_key': str(private_key),
               'known_hosts': str(known_hosts), 'allow_agent': False,
               'look_for_keys': False, 'max_tries': 1, 'timeout': 2}
    finally:
        stop.set()
        listener.close()
        thread.join(2)
        for transport in transports:
            transport.close()
        for worker in workers:
            worker.join(2)


class RealSFTPTests(unittest.TestCase):
    def test_unknown_and_changed_server_keys_are_rejected(self):
        for changed in (False, True):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                local = root / 'local'
                local.mkdir()
                with server(root) as options:
                    _raw, wrong_key = generate_key()
                    trusted = ('[127.0.0.1]:%s %s %s\n' %
                               (options['port'], wrong_key.get_name(), wrong_key.get_base64()))
                    Path(options['known_hosts']).write_text(trusted if changed else '')
                    uploader = SFTPUploader(local_root=str(local), remote_root='/pub', **options)
                    with self.assertLogs('user.sftp', level='ERROR'):
                        with self.assertRaises(OSError):
                            uploader.run()
                    self.assertFalse((root / 'pub').exists())
                    self.assertFalse((local / '#SFTP.last').exists())

    def test_key_upload_incremental_cache_and_destination_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local = root / 'local'
            remote = root / 'remote'
            local.mkdir()
            remote.mkdir()
            for name, content in [('index.html', b'<html>fixture</html>'),
                                  ('style.css', b'body{}'), ('app.js', b'void 0;'),
                                  ('image.png', b'\x89PNG\r\n')]:
                (local / name).write_bytes(content)
            with server(remote) as options:
                uploader = SFTPUploader(local_root=str(local), remote_root='/pub/site', **options)
                self.assertEqual(uploader.run(), 4)
                self.assertEqual(uploader.run(), 0)
                uploader.remote_root = '/another/site'
                self.assertEqual(uploader.run(), 4)
            for path in local.iterdir():
                if not path.name.startswith('#'):
                    self.assertEqual(path.read_bytes(), (remote / 'pub/site' / path.name).read_bytes())
                    self.assertEqual(path.read_bytes(), (remote / 'another/site' / path.name).read_bytes())

    def test_sftp_negotiation_timeout_after_successful_ssh_auth(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with server(root, silent=True) as options:
                options['timeout'] = 0.2
                uploader = SFTPUploader(local_root=str(root), remote_root='/pub', **options)
                started = time.monotonic()
                with self.assertLogs('user.sftp', level='ERROR') as logs:
                    with self.assertRaises(OSError):
                        uploader.run()
                self.assertIn('SFTP session negotiation timed out', '\n'.join(logs.output))
                self.assertLess(time.monotonic() - started, 3)
                self.assertFalse((root / '#SFTP.last').exists())

    def test_stalled_file_request_preserves_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local = root / 'local'
            local.mkdir()
            (local / 'blocked.html').write_text('data')
            with server(root, stalled=True) as options:
                options['timeout'] = 0.2
                uploader = SFTPUploader(local_root=str(local), remote_root='/pub', **options)
                uploader.save_last_upload(1, set())
                before = (local / '#SFTP.last').read_bytes()
                started = time.monotonic()
                with self.assertRaises(OSError):
                    uploader.run()
                self.assertLess(time.monotonic() - started, 3)
                self.assertEqual((local / '#SFTP.last').read_bytes(), before)

    def test_cli_inherits_report_root_and_key_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local = root / 'reports'
            local.mkdir()
            (local / 'index.html').write_text('CLI fixture')
            remote = root / 'remote'
            remote.mkdir()
            skin = root / 'skins/sftp'
            skin.mkdir(parents=True)
            (skin / 'skin.conf').write_text('[Generators]\n generator_list = user.sftp.SFTPGenerator\n')
            with server(remote) as options:
                config = root / 'weewx.conf'
                lines = ['[StdReport]', ' SKIN_ROOT = skins', ' HTML_ROOT = reports',
                         ' [[Upload]]', '  skin = sftp', '  path = /cli']
                lines += ['  %s = %s' % (key, value) for key, value in options.items()
                          if key != 'password']
                config.write_text('\n'.join(lines) + '\n')
                script = Path(__file__).resolve().parents[1] / 'bin/user/sftp.py'
                result = subprocess.run([sys.executable, str(script), '--config', str(config),
                                         '--report', 'Upload', '--debug'],
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((remote / 'cli/index.html').read_text(), 'CLI fixture')
                config.write_text(config.read_text().replace('user = alice', 'user = invalid'))
                failed = subprocess.run([sys.executable, str(script), '--config', str(config),
                                         '--report', 'Upload'],
                                        capture_output=True, text=True, timeout=15)
                self.assertNotEqual(failed.returncode, 0)
                self.assertNotIn('transferred ', failed.stderr)


if __name__ == '__main__':
    print('Testing real Paramiko %s against loopback SSH/SFTP' % paramiko.__version__, flush=True)
    unittest.main(verbosity=2)
