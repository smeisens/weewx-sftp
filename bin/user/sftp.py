# Copyright 2018 Matthew Wall
# Copyright 2025 - 2026 Sigi Meisenbichler
# Distributed under the terms of GPLv3
"""
Generator for weewx that uploads data using sftp.  Copy everything from a
designated local directory to a remote directory, using the sftp protocol.

This generator is intended to be functionally equivalent to the FTP generator
in weewx, but using a different protocol.

The sftp protocol is not the same as the ftps protocol!  The ftps protocol
is supported by the standard FTP generator in weewx.  This generator uses sftp,
which requires the paramiko module.

Based on the FTP generator in weewx, with help from the SFTP generator
implemented by davies-barnard.

Security notes (since 0.9):
  * The server's host key is always verified against a known_hosts file.
    Unknown or changed host keys abort the upload (no silent MITM).
  * Passwords and key passphrases can be read from environment variables,
    so they do not have to be stored in weewx.conf.
  * Upload state is stored as JSON instead of pickle.
"""

import json
import logging
import os
import posixpath
import time

import paramiko

import weewx
import weewx.reportengine
from weeutil.weeutil import to_bool

log = logging.getLogger(__name__)

VERSION = "0.9"

# paramiko < 3.4.0 is vulnerable to the Terrapin attack (CVE-2023-48795)
MIN_PARAMIKO = (3, 4, 0)

SKIP_DIRS = {'.svn', 'CVS', '.git'}


def logdbg(msg, label='sftp'):
    log.debug(f"{label}: {msg}")


def loginf(msg, label='sftp'):
    log.info(f"{label}: {msg}")


def logwarn(msg, label='sftp'):
    log.warning(f"{label}: {msg}")


def logerr(msg, label='sftp'):
    log.error(f"{label}: {msg}")


def paramiko_version():
    """Return the installed paramiko version as a tuple of ints."""
    try:
        return tuple(int(x) for x in paramiko.__version_info__[:3])
    except (AttributeError, TypeError, ValueError):
        parts = []
        for x in paramiko.__version__.split('.')[:3]:
            digits = ''.join(c for c in x if c.isdigit())
            parts.append(int(digits) if digits else 0)
        return tuple(parts)


def check_paramiko_version():
    if paramiko_version() < MIN_PARAMIKO:
        logwarn(f"paramiko {paramiko.__version__} is vulnerable to the "
                f"Terrapin attack (CVE-2023-48795); please upgrade to "
                f"paramiko >= {'.'.join(map(str, MIN_PARAMIKO))}")


def get_secret(skin_dict, key):
    """Read a secret either directly from the config (key) or from the
    environment variable named in key_env.  key_env wins if set."""
    env_name = skin_dict.get(f"{key}_env")
    if env_name:
        value = os.environ.get(env_name)
        if value is None:
            raise KeyError(f"environment variable '{env_name}' "
                           f"(from {key}_env) is not set")
        return value
    return skin_dict.get(key)


class AcceptNewHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Trust-on-first-use, like OpenSSH 'StrictHostKeyChecking accept-new':
    an unknown host key is accepted once and appended to known_hosts.
    A *changed* key is still rejected by paramiko (BadHostKeyException)."""

    def __init__(self, known_hosts):
        self.known_hosts = known_hosts

    def missing_host_key(self, client, hostname, key):
        client.get_host_keys().add(hostname, key.get_name(), key)
        directory = os.path.dirname(self.known_hosts)
        if directory:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        fd = os.open(self.known_hosts, os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                     0o600)
        with os.fdopen(fd, 'a') as f:
            f.write(f"{hostname} {key.get_name()} {key.get_base64()}\n")
        logwarn(f"accepted new host key for {hostname} "
                f"({key.get_name()} {key.fingerprint}) and saved it to "
                f"{self.known_hosts}")


class SFTPUploader(object):

    def __init__(self, server, user, password, local_root, remote_root,
                 private_key=None, private_key_pass=None,
                 known_hosts=None, accept_new_host_key=False,
                 port=22, name='SFTP', max_tries=3, timeout=30, debug=0):
        self.server = server
        self.user = user
        self.password = password
        self.private_key = os.path.expanduser(private_key) if private_key else None
        self.private_key_pass = private_key_pass
        self.known_hosts = os.path.expanduser(known_hosts) if known_hosts else None
        self.accept_new_host_key = accept_new_host_key
        self.local_root = os.path.realpath(local_root)
        self.remote_root = posixpath.normpath(remote_root)
        self.port = port
        self.name = name
        self.max_tries = max(1, max_tries)
        self.timeout = timeout
        self.debug = debug

        if self.accept_new_host_key and not self.known_hosts:
            raise ValueError("accept_new_host_key requires known_hosts")

        logdbg(f"local_root={self.local_root}")
        logdbg(f"remote_root={self.remote_root}")
        logdbg(f"server={server} port={port} user={user}")

    @property
    def state_file(self):
        return os.path.join(self.local_root, f"#{self.name}.last.json")

    @property
    def legacy_state_file(self):
        # pickle file written by versions <= 0.8
        return os.path.join(self.local_root, f"#{self.name}.last")

    def _connect(self):
        client = paramiko.SSHClient()
        # ~/.ssh/known_hosts of the weewx user plus the system-wide file
        client.load_system_host_keys()
        if os.path.isfile('/etc/ssh/ssh_known_hosts'):
            client.load_system_host_keys('/etc/ssh/ssh_known_hosts')
        if self.known_hosts and os.path.isfile(self.known_hosts):
            client.load_host_keys(self.known_hosts)
        if self.accept_new_host_key:
            client.set_missing_host_key_policy(
                AcceptNewHostKeyPolicy(self.known_hosts))
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        kwargs = dict(hostname=self.server, port=self.port,
                      username=self.user,
                      timeout=self.timeout, banner_timeout=self.timeout,
                      auth_timeout=self.timeout,
                      look_for_keys=False, allow_agent=False)
        if self.password:
            kwargs['password'] = self.password
        if self.private_key:
            kwargs['key_filename'] = self.private_key
            if self.private_key_pass:
                kwargs['passphrase'] = self.private_key_pass
        try:
            client.connect(**kwargs)
        except Exception:
            client.close()
            raise
        return client

    def run(self):
        n_uploaded = 0
        (last_ts, fileset) = self.get_last_upload()
        # Take the timestamp *before* scanning, so files changed during the
        # upload are picked up again on the next run.
        run_ts = time.time()
        client = None
        sftp = None
        try:
            logdbg(f"connecting to {self.user}@{self.server}:{self.port}")
            client = self._connect()
            sftp = client.open_sftp()
            sftp.get_channel().settimeout(self.timeout)
            known_dirs = set()

            for dirpath, dirnames, filenames in os.walk(self.local_root):
                # do not descend into VCS directories
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

                local_rel_dir = os.path.relpath(dirpath, self.local_root)
                if local_rel_dir == '.':
                    remote_dir = self.remote_root
                else:
                    remote_dir = posixpath.normpath(posixpath.join(
                        self.remote_root, *local_rel_dir.split(os.sep)))

                pending = [f for f in filenames
                           if not self._skip_file(last_ts, fileset,
                                                  os.path.join(dirpath, f))]
                if not pending:
                    continue

                self._make_remote_dir(sftp, remote_dir, known_dirs)

                for filename in pending:
                    local_path = os.path.join(dirpath, filename)
                    remote_path = posixpath.join(remote_dir, filename)
                    if self._upload(client, sftp, local_path, remote_path):
                        n_uploaded += 1
                        fileset.add(local_path)
                    else:
                        # make sure it is retried next time
                        fileset.discard(local_path)

        except paramiko.BadHostKeyException as e:
            logerr(f"HOST KEY MISMATCH for {self.server}! Possible "
                   f"man-in-the-middle attack, upload aborted: {e}")
            return n_uploaded
        except paramiko.SSHException as e:
            if 'not found in known_hosts' in str(e):
                logerr(f"unknown host key for {self.server}:{self.port}, "
                       f"upload aborted. Add the server to known_hosts "
                       f"(e.g. with ssh-keyscan) or set accept_new_host_key")
            else:
                logerr(f"connection or upload failed: {e}")
            return n_uploaded
        except Exception as e:
            logerr(f"connection or upload failed: {e}")
            return n_uploaded
        finally:
            if sftp:
                sftp.close()
            if client:
                client.close()

        self.save_last_upload(run_ts, fileset)
        return n_uploaded

    def _upload(self, client, sftp, local_path, remote_path):
        for cnt in range(self.max_tries):
            try:
                sftp.put(local_path, remote_path)
            except (OSError, IOError, paramiko.SSHException) as e:
                loginf(f"attempt {cnt + 1} of {self.max_tries} for "
                       f"{remote_path} failed: {e}")
                transport = client.get_transport()
                if transport is None or not transport.is_active():
                    raise paramiko.SSHException("connection lost")
            else:
                logdbg(f"uploaded file {remote_path}")
                return True
        logerr(f"failed to upload file {remote_path}")
        return False

    def get_last_upload(self):
        # Remove the pickle state of older versions without loading it.
        try:
            os.remove(self.legacy_state_file)
        except OSError:
            pass
        try:
            with open(self.state_file, "r") as f:
                data = json.load(f)
            timestamp = float(data['timestamp'])
            fileset = set(str(x) for x in data['files'])
        except (OSError, ValueError, KeyError, TypeError):
            timestamp = 0
            fileset = set()
        return (timestamp, fileset)

    def save_last_upload(self, timestamp, fileset):
        tmp = self.state_file + '.tmp'
        try:
            with open(tmp, "w") as f:
                json.dump({'timestamp': timestamp,
                           'files': sorted(fileset)}, f)
            os.replace(tmp, self.state_file)
        except OSError as e:
            loginf(f"failed to save upload time: {e}")

    @staticmethod
    def _make_remote_dir(sftp, remote_dir, known_dirs):
        if remote_dir in known_dirs:
            return
        path = '/' if remote_dir.startswith('/') else ''
        for part in [p for p in remote_dir.split('/') if p]:
            path = posixpath.join(path, part) if path else part
            if path in known_dirs:
                continue
            try:
                sftp.stat(path)
            except IOError:
                try:
                    sftp.mkdir(path)
                    logdbg(f"created remote directory {path}")
                except IOError as e:
                    logdbg(f"failed to create directory {path}: {e}")
            known_dirs.add(path)

    def _skip_file(self, timestamp, fileset, local_path):
        filename = os.path.basename(local_path)
        if filename.startswith('#') or filename.startswith('.#') \
                or filename.endswith('~'):
            return True

        # Never follow symlinks out of the local root
        real = os.path.realpath(local_path)
        if os.path.commonpath([real, self.local_root]) != self.local_root:
            logdbg(f"skipping {local_path}: points outside {self.local_root}")
            return True

        if local_path not in fileset:
            return False

        try:
            return os.stat(local_path).st_mtime <= timestamp
        except OSError:
            return True


class SFTPGenerator(weewx.reportengine.ReportGenerator):

    def run(self):
        log_success = to_bool(self.skin_dict.get('log_success', True))
        t1 = time.time()

        if 'HTML_ROOT' in self.skin_dict:
            local_root = os.path.join(
                self.config_dict['WEEWX_ROOT'],
                self.skin_dict['HTML_ROOT'])
        else:
            local_root = os.path.join(
                self.config_dict['WEEWX_ROOT'],
                self.config_dict.get('StdReport', {}).get('HTML_ROOT', 'public_html'))

        logdbg(f"running SFTPGenerator {VERSION}")
        check_paramiko_version()

        try:
            uploader = SFTPUploader(
                server=self.skin_dict['server'],
                user=self.skin_dict['user'],
                password=get_secret(self.skin_dict, 'password'),
                private_key=self.skin_dict.get('private_key'),
                private_key_pass=get_secret(self.skin_dict, 'private_key_pass'),
                known_hosts=self.skin_dict.get('known_hosts'),
                accept_new_host_key=to_bool(
                    self.skin_dict.get('accept_new_host_key', False)),
                local_root=local_root,
                remote_root=self.skin_dict['path'],
                port=int(self.skin_dict.get('port', 22)),
                name=self.skin_dict.get('REPORT_NAME', 'SFTP'),
                max_tries=int(self.skin_dict.get('max_tries', 3)),
                timeout=float(self.skin_dict.get('timeout', 30)),
                debug=int(self.skin_dict.get('debug', 0))
            )
        except (KeyError, ValueError) as e:
            logerr(f"upload not possible: {e}", "sftpgenerator")
            return

        try:
            n = uploader.run()
        except Exception as e:
            logerr(f"{e}", "sftpgenerator")
            return

        t2 = time.time()
        if log_success:
            loginf(f"transferred {n} files in {t2 - t1:.2f} seconds",
                   "sftpgenerator")


# entry point for testing this code
if __name__ == '__main__':
    import argparse
    import configobj
    import weeutil.logger

    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/weewx/weewx.conf",
                        help="weewx configuration file")
    parser.add_argument("--report", default="SFTP",
                        help="report section in [StdReport]")
    parser.add_argument("--debug", action="store_true",
                        help="enable verbose logging")
    options = parser.parse_args()

    cfg = configobj.ConfigObj(options.config, file_error=True)
    if options.debug:
        weewx.debug = 1
    weeutil.logger.setup('sftp', cfg)

    stdrep = cfg.get('StdReport', {})
    skin = dict(stdrep.get(options.report, {}))
    skin.setdefault('REPORT_NAME', options.report)
    config_dict = {
        'WEEWX_ROOT': cfg.get('WEEWX_ROOT', '/etc/weewx'),
        'StdReport': {'HTML_ROOT': stdrep.get('HTML_ROOT', 'public_html')},
    }

    print(f"connect to {skin.get('server')}:{skin.get('port', 22)}")
    print(f"destination: {skin.get('path')}")
    print(f"username: {skin.get('user')}")
    gen = SFTPGenerator(config_dict, skin, gen_ts=None, first_run=None,
                        stn_info=None)
    gen.run()
