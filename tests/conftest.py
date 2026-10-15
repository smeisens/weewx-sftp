"""Test bootstrap.

The extension imports ``weewx`` / ``weeutil`` at module load and imports
``paramiko`` lazily inside ``SFTPUploader``.  Neither is required to unit-test
the file's logic, so:

* ``bin/`` is put on ``sys.path`` so ``import user.sftp`` works;
* ``weewx`` / ``weeutil.weeutil`` are stubbed only if a real WeeWX is not
  installed (CI installs one in a separate integration job);
* ``paramiko`` is always replaced with an in-memory fake -- the unit tests
  never touch a real SSH server.
"""

import os
import stat as stat_module
import sys
import types

BIN_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, "bin"))
if BIN_DIR not in sys.path:
    sys.path.insert(0, BIN_DIR)


def _ensure_weewx_stubs():
    try:
        import weewx  # noqa: F401
        import weewx.reportengine  # noqa: F401
        from weeutil.weeutil import to_bool  # noqa: F401

        return  # a real WeeWX is importable; use it
    except ImportError:
        pass

    weewx = types.ModuleType("weewx")
    weewx.__version__ = "0.0.0-stub"
    weewx.debug = 0

    reportengine = types.ModuleType("weewx.reportengine")

    class ReportGenerator:
        def __init__(
            self,
            config_dict=None,
            skin_dict=None,
            gen_ts=None,
            first_run=None,
            stn_info=None,
            record=None,
        ):
            self.config_dict = config_dict or {}
            self.skin_dict = skin_dict or {}
            self.gen_ts = gen_ts
            self.first_run = first_run
            self.stn_info = stn_info
            self.record = record

    reportengine.ReportGenerator = ReportGenerator
    weewx.reportengine = reportengine

    weeutil = types.ModuleType("weeutil")
    weeutil_weeutil = types.ModuleType("weeutil.weeutil")

    def to_bool(value):
        try:
            if value.lower() in ("true", "yes", "y"):
                return True
            if value.lower() in ("false", "no", "n"):
                return False
        except AttributeError:
            pass
        try:
            return bool(int(value))
        except (ValueError, TypeError):
            pass
        raise ValueError("Unknown boolean specifier: '%s'." % (value,))

    weeutil_weeutil.to_bool = to_bool
    weeutil.weeutil = weeutil_weeutil

    for name, mod in (
        ("weewx", weewx),
        ("weewx.reportengine", reportengine),
        ("weeutil", weeutil),
        ("weeutil.weeutil", weeutil_weeutil),
    ):
        sys.modules[name] = mod


def _install_fake_paramiko():
    mod = types.ModuleType("paramiko")

    class SSHException(Exception):
        pass

    class AutoAddPolicy:
        pass

    class RejectPolicy:
        pass

    mod.SSHException = SSHException
    mod.AutoAddPolicy = AutoAddPolicy
    mod.RejectPolicy = RejectPolicy
    mod.SSHClient = None  # the paramiko_stub fixture supplies a working one
    sys.modules["paramiko"] = mod


_ensure_weewx_stubs()
_install_fake_paramiko()

import pytest  # noqa: E402


class RecordingSFTP:
    """Stand-in for ``paramiko.SFTPClient``."""

    def __init__(self):
        self.put_calls = []
        self.mkdir_calls = []
        self.stat_calls = []
        self.closed = False
        self.existing_dirs = {'/', '.'}
        self.put_errors = {}  # remote path -> exception to raise once
        self.timeout = None

    def get_channel(self):
        return self

    def settimeout(self, timeout):
        self.timeout = timeout

    def stat(self, path):
        self.stat_calls.append(path)
        if path in self.existing_dirs:
            return types.SimpleNamespace(st_mode=stat_module.S_IFDIR | 0o755)
        raise OSError(2, "No such file", path)

    def mkdir(self, path):
        self.mkdir_calls.append(path)
        self.existing_dirs.add(path)

    def put(self, local, remote):
        self.put_calls.append((local, remote))
        err = self.put_errors.pop(remote, None)
        if err is not None:
            raise err

    def close(self):
        self.closed = True


@pytest.fixture
def paramiko_stub(monkeypatch):
    """Give ``paramiko.SSHClient`` a recording fake.

    ``state["fail_first"]`` makes that many ``connect()`` calls raise
    ``SSHException`` before one succeeds; ``state["clients"]`` lists every
    client the code under test constructed.
    """
    mod = sys.modules["paramiko"]
    state = {"clients": [], "attempts": 0, "fail_first": 0}

    class SSHClient:
        def __init__(self):
            self.connect_calls = []
            self.policy = None
            self.host_keys_loaded = False
            self.closed = False
            self.sftp = RecordingSFTP()
            state["clients"].append(self)

        def load_system_host_keys(self):
            self.host_keys_loaded = True

        def load_host_keys(self, path):
            with open(path):
                pass
            self.known_hosts = path

        def set_missing_host_key_policy(self, policy):
            self.policy = policy

        def connect(self, **kwargs):
            self.connect_calls.append(kwargs)
            state["attempts"] += 1
            if state["attempts"] <= state["fail_first"]:
                raise mod.SSHException("simulated connect failure")

        def open_sftp(self):
            return self.sftp

        def close(self):
            self.closed = True

    monkeypatch.setattr(mod, "SSHClient", SSHClient)
    mod._state = state
    return mod
