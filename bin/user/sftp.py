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
"""

# sftp.py - WeeWX SFTP Generator mit Paramiko (anstatt pysftp)

import os
import time
import paramiko
import weewx
import weewx.reportengine
from weeutil.weeutil import to_bool
import logging

log = logging.getLogger(__name__)

def logdbg(msg, label=None):
    if label is None:
        label = 'sftp'
    log.debug(f"{label}: {msg}")

def loginf(msg, label=None):
    if label is None:
        label = 'sftp'
    log.info(f"{label}: {msg}")

def logerr(msg, label=None):
    if label is None:
        label = 'sftp'
    log.error(f"{label}: {msg}")


VERSION = "0.8"


class SFTPUploader(object):

    def __init__(self, server, user, password, local_root, remote_root,
                 private_key=None, private_key_pass=None,
                 port=22, name='SFTP', max_tries=3, debug=0):
        self.server = server
        self.user = user
        self.password = password
        self.private_key = private_key
        self.private_key_pass = private_key_pass
        self.local_root = os.path.normpath(local_root)
        self.remote_root = os.path.normpath(remote_root)
        self.port = port
        self.name = name
        self.max_tries = max_tries
        self.debug = debug

        logdbg(f"local_root={self.local_root}")
        logdbg(f"remote_root={self.remote_root}")
        logdbg(f"server={server} port={port} user={user}")

    def run(self):
        n_uploaded = 0
        (timestamp, fileset) = self.get_last_upload()
        transport = None
        sftp = None
        try:
            logdbg(f"connecting to {self.user}@{self.server}")

            # Transport aufbauen
            transport = paramiko.Transport((self.server, self.port))
            if self.private_key:
                pkey = paramiko.RSAKey.from_private_key_file(self.private_key, password=self.private_key_pass)
                transport.connect(username=self.user, pkey=pkey)
            else:
                transport.connect(username=self.user, password=self.password)

            sftp = paramiko.SFTPClient.from_transport(transport)

            for dirpath, unused_dirs, filenames in os.walk(self.local_root):
                # relativen Pfad vom lokalen Wurzelverzeichnis bilden
                local_rel_dir_path = os.path.relpath(dirpath, self.local_root)
                if self._skip_dir(local_rel_dir_path):
                    continue

                # Remote-Pfad zusammenbauen
                remote_dir_path = os.path.normpath(os.path.join(self.remote_root, local_rel_dir_path))

                # Remote Verzeichnis erstellen, falls nicht vorhanden
                self._make_remote_dir(sftp, remote_dir_path)

                # Dateien hochladen
                for filename in filenames:
                    full_local_path = os.path.join(dirpath, filename)

                    if self._skip_file(timestamp, fileset, full_local_path):
                        continue

                    full_remote_path = os.path.join(remote_dir_path, filename)

                    for cnt in range(self.max_tries):
                        try:
                            sftp.put(full_local_path, full_remote_path)
                        except (OSError, IOError) as e:
                            loginf(f"attempt {cnt + 1} of {self.max_tries} failed: {e}")
                        else:
                            n_uploaded += 1
                            fileset.add(full_local_path)
                            logdbg(f"uploaded file {full_remote_path}")
                            break
                    else:
                        logerr(f"failed to upload file {full_remote_path}")

        except Exception as e:
            logerr(f"Connection or upload failed: {e}")
        finally:
            if sftp:
                sftp.close()
            if transport:
                transport.close()

        timestamp = time.time()
        self.save_last_upload(timestamp, fileset)
        return n_uploaded

    def get_last_upload(self):
        import pickle
        tsfile = os.path.join(self.local_root, f"#{self.name}.last")
        try:
            with open(tsfile, "rb") as f:
                timestamp = pickle.load(f)
                fileset = pickle.load(f)
        except (IOError, EOFError, pickle.PickleError):
            timestamp = 0
            fileset = set()
            try:
                os.remove(tsfile)
            except OSError:
                pass
        return (timestamp, fileset)

    def save_last_upload(self, timestamp, fileset):
        import pickle
        tsfile = os.path.join(self.local_root, f"#{self.name}.last")
        try:
            with open(tsfile, "wb") as f:
                pickle.dump(timestamp, f)
                pickle.dump(fileset, f)
        except IOError as e:
            loginf(f"failed to save upload time: {e}")

    def _make_remote_dir(self, sftp, remote_dir_path):
        logdbg(f"create remote directory {remote_dir_path}")
        parts = remote_dir_path.strip('/').split('/')
        path = ''
        for part in parts:
            path += '/' + part
            try:
                sftp.stat(path)
            except IOError:
                try:
                    sftp.mkdir(path)
                    logdbg(f"created remote directory {path}")
                except Exception as e:
                    logdbg(f"failed to create directory {path}: {e}")

    def _skip_dir(self, local_dir):
        for x in ['.svn', 'CVS', '.git']:
            if x in local_dir:
                return True
        return False

    def _skip_file(self, timestamp, fileset, full_local_path):
        filename = os.path.basename(full_local_path)
        if (filename.startswith('#') or filename.startswith('.#') or filename.endswith('~')):
            return True

        if full_local_path not in fileset:
            return False

        ftime = os.stat(full_local_path).st_mtime
        if ftime > timestamp:
            return False

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

        try:
            uploader = SFTPUploader(
                server=self.skin_dict['server'],
                user=self.skin_dict['user'],
                password=self.skin_dict.get('password'),
                private_key=self.skin_dict.get('private_key'),
                private_key_pass=self.skin_dict.get('private_key_pass'),
                local_root=local_root,
                remote_root=self.skin_dict['path'],
                port=int(self.skin_dict.get('port', 22)),
                name=self.skin_dict.get('REPORT_NAME', 'SFTP'),
                max_tries=int(self.skin_dict.get('max_tries', 3)),
                debug=int(self.skin_dict.get('debug', 0))
            )
        except KeyError as e:
            loginf(f"upload not possible: missing parameter {e}", "sftpgenerator")
            return
        except ImportError as e:
            loginf(f"upload not possible: {e}", "sftpgenerator")
            return

        try:
            n = uploader.run()
        except Exception as e:
            logerr(f"{e}", "sftpgenerator")
            return

        t2 = time.time()
        if log_success:
            loginf(f"transferred {n} files in {t2 - t1:.2f} seconds", "sftpgenerator")


# entry point for testing this code (optional)
if __name__ == '__main__':
    import configobj
    import optparse
    import socket

    parser = optparse.OptionParser()
    parser.add_option("--config", dest="config_path", metavar="CONFIG_FILE",
                      default="/home/weewx/weewx.conf",
                      help="Use configuration file CONFIG_FILE")
    parser.add_option("--report", default="SFTP",
                      help="Use the specified report from StdReport")
    parser.add_option("--debug", action="store_true",
                      help="Enable verbose logging")
    (options, args) = parser.parse_args()

    debug = 0
    if options.debug:
        weewx.debug = 1
        debug = 1

    cfg = dict()
    try:
        cfg = configobj.ConfigObj(options.config_path)
    except IOError:
        pass

    stdrep = cfg.get('StdReport', {})
    skin = stdrep.get(options.report, {})
    config_dict = {
        'WEEWX_ROOT': cfg.get('WEEWX_ROOT', '/home/weewx'),
        'StdReport': {
            'HTML_ROOT': stdrep.get('HTML_ROOT', '/var/www/html')
        }
    }
    skin_dict = {
        'server': skin.get('server', 'localhost'),
        'port': skin.get('port', 22),
        'user': skin.get('user', 'username'),
        'password': skin.get('password', 'password'),
        'path': skin.get('path', '/pub'),
        'debug': skin.get('debug', debug),
    }

    print(f"connect to {skin_dict['server']}:{skin_dict['port']}")
    print(f"destination: {skin_dict['path']}")
    print(f"username: {skin_dict['user']}")
    socket.setdefaulttimeout(10)
    gen = SFTPGenerator(config_dict, skin_dict, gen_ts=None, first_run=None, stn_info=None)
    gen.run()
