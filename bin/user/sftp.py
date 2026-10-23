# Copyright 2018 Matthew Wall
# Distributed under the terms of GPLv3
"""
Generator for weewx that uploads data using sftp.  Copy everything from a
designated local directory to a remote directory, using the sftp protocol.

This generator is intended to be functionally equivalent to the FTP generator
in weewx, but using a different protocol.

The sftp protocol is not the same as the ftps protocol!  The ftps protocol
is supported by the standard FTP generator in weewx.  This generator uses sftp,
which uses the Paramiko SSH/SFTP library.

Based on the FTP generator in weewx, with help from the SFTP generator
implemented by davies-barnard.
"""

import logging
import math
import os
import pickle
import posixpath
import re
import stat
import tempfile
import threading
import time

import weewx
import weewx.reportengine
from weeutil.weeutil import to_bool

log = logging.getLogger(__name__)


def logdbg(msg, label='sftp'):
    log.debug("%s: %s" % (label, msg))


def loginf(msg, label='sftp'):
    log.info("%s: %s" % (label, msg))


def logwarn(msg, label='sftp'):
    log.warning("%s: %s" % (label, msg))


def logerr(msg, label='sftp'):
    log.error("%s: %s" % (label, msg))


VERSION = "0.9.0"

# paramiko 3.4.0 added "strict kex", the client-side fix for the Terrapin
# prefix-truncation attack (CVE-2023-48795).
MIN_SAFE_PARAMIKO = (3, 4, 0)
_paramiko_version_checked = False


def paramiko_version(module):
    """Return the version of a paramiko module as a tuple of ints, or None."""
    info = getattr(module, '__version_info__', None)
    if info is not None:
        try:
            return tuple(int(x) for x in info[:3])
        except (TypeError, ValueError):
            pass
    match = re.match(r'(\d+)\.(\d+)(?:\.(\d+))?', str(getattr(module, '__version__', '')))
    if match is None:
        return None
    return tuple(int(x or 0) for x in match.groups())


def check_paramiko_version(module):
    """Warn once per process if paramiko is vulnerable to Terrapin."""
    global _paramiko_version_checked
    if _paramiko_version_checked:
        return
    _paramiko_version_checked = True
    version = paramiko_version(module)
    if version is not None and version < MIN_SAFE_PARAMIKO:
        logwarn("paramiko %s is vulnerable to the Terrapin attack (CVE-2023-48795); "
                "upgrade to %s or newer" % (getattr(module, '__version__', version),
                                            '.'.join(str(x) for x in MIN_SAFE_PARAMIKO)))


class SFTPUploader(object):

    def __init__(self, server, user, password, local_root, remote_root,
                 private_key=None, private_key_pass=None,
                 port=22, name='SFTP', max_tries=3, debug=0,
                 timeout=30, known_hosts=None, allow_agent=True,
                 look_for_keys=True, log_progress=False,
                 allow_external_symlinks=False):
        import paramiko  # noqa: F401  -- fail fast if the dependency is missing
        self.server = server
        self.user = user
        self.password = password
        self.private_key = private_key
        self.private_key_pass = private_key_pass
        self.local_root = os.path.normpath(local_root)
        self.remote_root = posixpath.normpath(remote_root)
        self.port = port
        self.name = name
        self.max_tries = int(max_tries)
        self.timeout = float(timeout)
        if self.max_tries < 1 or not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValueError("max_tries and timeout must be positive (timeout must be finite)")
        self.known_hosts = known_hosts
        self.allow_agent = to_bool(allow_agent)
        self.look_for_keys = to_bool(look_for_keys)
        self.log_progress = to_bool(log_progress)
        self.allow_external_symlinks = to_bool(allow_external_symlinks)
        self.debug = debug
        logdbg("local_root=%s" % self.local_root)
        logdbg("remote_root=%s" % self.remote_root)
        logdbg("server=%s port=%s user=%s" % (server, port, user))

    def run(self):
        import paramiko
        check_paramiko_version(paramiko)
        if not os.path.isdir(self.local_root):
            raise OSError("local report directory does not exist: %s" % self.local_root)
        started = time.time()
        n_uploaded = 0
        (timestamp, fileset) = self.get_last_upload()
        client = None
        con = None
        try:
            loginf("starting upload from %s to %s:%s" %
                   (self.local_root, self.server, self.remote_root), self.name)
            for cnt in range(self.max_tries):
                try:
                    client = paramiko.SSHClient()
                    if self.known_hosts:
                        client.load_host_keys(os.path.expanduser(self.known_hosts))
                        client.set_missing_host_key_policy(paramiko.RejectPolicy())
                    else:
                        # Retain legacy behavior unless verification is configured.
                        client.load_system_host_keys()
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                    connect_args = {
                        'hostname': self.server,
                        'username': self.user,
                        'port': self.port,
                        'timeout': self.timeout,
                        'banner_timeout': self.timeout,
                        'auth_timeout': self.timeout,
                        'allow_agent': self.allow_agent,
                        'look_for_keys': self.look_for_keys,
                    }
                    if self.password is not None:
                        connect_args['password'] = self.password
                    if self.private_key is not None:
                        connect_args['key_filename'] = self.private_key
                    if self.private_key_pass is not None:
                        connect_args['passphrase'] = self.private_key_pass

                    client.connect(**connect_args)
                    loginf("authenticated; opening SFTP session", self.name)
                    con = self._open_sftp(client)
                    loginf("SFTP session opened", self.name)
                    break
                except (paramiko.SSHException, OSError) as e:
                    logerr("connect %s of %s failed: %s" %
                           (cnt + 1, self.max_tries, e))
                    if con is not None:
                        try:
                            con.close()
                        except Exception:
                            pass
                        con = None
                    if client is not None:
                        try:
                            client.close()
                        except Exception:
                            pass
                        client = None
            else:
                logerr("failed %s attempts for %s@%s" %
                       (self.max_tries, self.user, self.server))
                raise OSError("SFTP connection retries exhausted")

            def walk_error(error):
                raise error

            real_root = os.path.realpath(self.local_root)

            for dirpath, dirs, filenames in os.walk(self.local_root, onerror=walk_error):
                dirs[:] = [d for d in dirs if not self._skip_dir(d)]
                # strip out the common local root directory
                local_rel_dir_path = os.path.relpath(dirpath, self.local_root)
                if self._skip_dir(local_rel_dir_path):
                    continue
                # this is the absolute path to the remote directory
                remote_dir_path = posixpath.normpath(posixpath.join(
                    self.remote_root, *local_rel_dir_path.split(os.sep)))
                # create the remote directory
                self._make_remote_dir(con, remote_dir_path)
                # iterate over all members of the local directory
                for filename in filenames:
                    full_local_path = os.path.join(dirpath, filename)
                    if self._points_outside(real_root, full_local_path):
                        loginf("skipping %s: symlink target is outside %s" %
                               (full_local_path, self.local_root), self.name)
                        continue
                    # see if this file can be skipped
                    if self._skip_file(timestamp, fileset, full_local_path):
                        continue
                    if not stat.S_ISREG(os.stat(full_local_path).st_mode):
                        raise OSError("refusing to upload non-regular file: %s" % full_local_path)
                    full_remote_path = posixpath.join(remote_dir_path, filename)
                    if self.log_progress:
                        loginf("uploading %s" % full_remote_path, self.name)
                    for cnt in range(self.max_tries):
                        try:
                            con.put(full_local_path, full_remote_path)
                        except OSError as e:
                            loginf("attempt %s of %s failed: %s" %
                                   (cnt + 1, self.max_tries, e))
                        else:
                            n_uploaded += 1
                            fileset.add(full_local_path)
                            if self.log_progress:
                                loginf("uploaded %s" % full_remote_path, self.name)
                            else:
                                logdbg("uploaded file %s" % full_remote_path)
                            break
                    else:
                        logerr("failed to upload file %s" % full_remote_path)
                        raise OSError("failed to upload file %s" % full_remote_path)
        finally:
            if con is not None:
                try:
                    con.close()
                except Exception:
                    pass
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass
        # Use the start time so a file modified during upload is retried next run.
        self.save_last_upload(started, fileset)
        return n_uploaded

    def _open_sftp(self, client):
        """Bound channel/subsystem negotiation as well as later SFTP I/O.

        Setting a channel timeout only *after* open_sftp returns does not cover
        a server that accepts SSH authentication but never answers SFTP INIT.
        Closing the client releases Paramiko's negotiation waits.
        """
        expired = threading.Event()

        def abort():
            expired.set()
            client.close()

        guard = threading.Timer(self.timeout, abort)
        guard.daemon = True
        guard.start()
        con = None
        try:
            con = client.open_sftp()
            if expired.is_set():
                raise TimeoutError("SFTP session negotiation timed out")
            con.get_channel().settimeout(self.timeout)
            return con
        except Exception as error:
            if con is not None:
                con.close()
            if expired.is_set():
                raise TimeoutError("SFTP session negotiation timed out") from error
            raise
        finally:
            guard.cancel()

    def _target(self):
        return (self.server, int(self.port), self.user, self.remote_root)

    def get_last_upload(self):
        """read the time and members of the last upload from local root"""
        tsfile = os.path.join(self.local_root, "#%s.last" % self.name)
        try:
            with open(tsfile, "rb") as f:
                timestamp = pickle.load(f)
                fileset = pickle.load(f)
                try:
                    target = pickle.load(f)
                except EOFError:
                    target = None
            if target != self._target():
                loginf("upload destination changed or cache is legacy; uploading all files",
                       self.name)
                return (0, set())
        except (OSError, EOFError, pickle.PickleError):
            timestamp = 0
            fileset = set()
            try:
                os.remove(tsfile)
            except OSError:
                pass
        return (timestamp, fileset)

    def save_last_upload(self, timestamp, fileset):
        """save the time and members of the last upload in the local root"""
        tsfile = os.path.join(self.local_root, "#%s.last" % self.name)
        fd, staged = tempfile.mkstemp(prefix=".#sftp-", dir=self.local_root)
        try:
            with os.fdopen(fd, "wb") as f:
                pickle.dump(timestamp, f)
                pickle.dump(fileset, f)
                pickle.dump(self._target(), f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(staged, tsfile)
        finally:
            if os.path.exists(staged):
                os.unlink(staged)

    def _remote_isdir(self, con, remote_dir_path):
        """return True if remote_dir_path exists and is a directory"""
        try:
            return stat.S_ISDIR(con.stat(remote_dir_path).st_mode)
        except OSError:
            return False

    def _make_remote_dir(self, con, remote_dir_path):
        """create remote directory using the server connection"""
        logdbg("create remote directory %s" % remote_dir_path)
        for _ in range(self.max_tries):
            try:
                if not self._remote_isdir(con, remote_dir_path):
                    parent = posixpath.dirname(remote_dir_path)
                    if parent and parent != remote_dir_path and not self._remote_isdir(con, parent):
                        self._make_remote_dir(con, parent)
                    con.mkdir(remote_dir_path)
                break
            except OSError as e:
                logdbg("create remote directory failed: %s" % e)
        else:
            raise OSError("failed to create remote directory %s" % remote_dir_path)

    def _points_outside(self, real_root, full_local_path):
        """True if a symlink resolves to a path outside the local root.

        Without this a link such as ``public_html/x -> /etc/weewx/weewx.conf``
        would publish the target's contents on the web server.
        """
        if self.allow_external_symlinks:
            return False
        real_path = os.path.realpath(full_local_path)
        try:
            return os.path.commonpath([real_root, real_path]) != real_root
        except ValueError:  # different drives on Windows
            return True

    def _skip_dir(self, local_dir):
        return any(x in os.path.normpath(local_dir).split(os.sep) for x in ('.svn', 'CVS', '.git'))

    def _skip_file(self, timestamp, fileset, full_local_path):
        # resolve the local file
        filename = os.path.basename(full_local_path)

        # ignore temporary files
        if (filename[0] == '#' or
            filename.startswith('.#') or
            filename[-1] == '~'):
            return True

        # does the file appear in the fileset?
        flag = True
        if full_local_path not in fileset:
            flag = False

        # has the file been updated/changed since last upload?
        ftime = os.stat(full_local_path).st_mtime
        if ftime > timestamp:
            flag = False

        return flag


def get_secret(skin_dict, option):
    """Return a secret option, either inline or from an environment variable.

    ``<option>_env`` names an environment variable that holds the value, so
    the secret does not have to be stored in weewx.conf.  Setting both forms
    is ambiguous and rejected, as is a named variable that is unset or empty.
    """
    env_name = skin_dict.get('%s_env' % option)
    if not env_name:
        return skin_dict.get(option)
    if skin_dict.get(option) is not None:
        raise ValueError("set either %s or %s_env, not both" % (option, option))
    value = os.environ.get(env_name)
    if not value:
        raise ValueError("environment variable %s (from %s_env) is not set or empty"
                         % (env_name, option))
    return value


class SFTPGenerator(weewx.reportengine.ReportGenerator):

    def run(self):
        self.success = False
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

        logdbg("running SFTPGenerator %s" % VERSION)

        try:
            uploader = SFTPUploader(
                server=self.skin_dict['server'],
                user=self.skin_dict['user'],
                password=get_secret(self.skin_dict, 'password'),
                private_key=self.skin_dict.get('private_key'),
                private_key_pass=get_secret(self.skin_dict, 'private_key_pass'),
                local_root=local_root,
                remote_root=self.skin_dict['path'],
                port=int(self.skin_dict.get('port', 22)),
                name=self.skin_dict.get('REPORT_NAME', 'SFTP'),
                max_tries=int(self.skin_dict.get('max_tries', 3)),
                debug=int(self.skin_dict.get('debug', 0)),
                timeout=self.skin_dict.get('timeout', 30),
                known_hosts=self.skin_dict.get('known_hosts'),
                allow_agent=self.skin_dict.get('allow_agent', True),
                look_for_keys=self.skin_dict.get('look_for_keys', True),
                log_progress=self.skin_dict.get('log_progress', False),
                allow_external_symlinks=self.skin_dict.get('allow_external_symlinks', False))
        except KeyError as e:
            loginf("upload not possible: missing parameter %s" % e,
                   "sftpgenerator")
            return
        except ImportError as e:
            loginf("upload not possible: %s" % e, "sftpgenerator")
            return
        except (TypeError, ValueError) as e:
            logerr("invalid configuration: %s" % e, self.skin_dict.get('REPORT_NAME', 'SFTP'))
            return

        try:
            n = uploader.run()
        except Exception as e:
            logerr("upload failed: %s" % e, self.skin_dict.get('REPORT_NAME', 'SFTP'))
            return

        t2 = time.time()
        self.success = True
        if log_success:
            loginf("transferred %d files in %0.2f seconds" % (n, (t2 - t1)),
                   "sftpgenerator")


def main():
    """Run the same effective report configuration used by the WeeWX engine."""
    import optparse

    import weecfg

    parser = optparse.OptionParser()
    parser.add_option("--config", dest="config_path", metavar="CONFIG_FILE",
                      help="Use configuration file CONFIG_FILE")
    parser.add_option("--report", default="SFTP",
                      help="Use the specified report from StdReport")
    parser.add_option("--debug", action="store_true", help="Enable verbose logging")
    options, args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if options.debug else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    try:
        _, config = weecfg.read_config(options.config_path, args)
        if options.report not in config.get('StdReport', {}):
            raise ValueError("report not found: %s" % options.report)
        skin = weewx.reportengine.build_skin_dict(config, options.report)
        if options.debug:
            skin['debug'] = 1
            skin['log_progress'] = True
        generator = SFTPGenerator(config, skin, None, None, None)
        generator.run()
        return 0 if generator.success else 1
    except Exception as error:
        logerr("command-line upload failed: %s" % error)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
