<p align="center">
  <img src="assets/weewx-sftp-logo.png" alt="weewx-sftp" width="360">
</p>

# weewx-sftp

[![CI](https://github.com/ziti/weewx-sftp/actions/workflows/ci.yml/badge.svg)](https://github.com/ziti/weewx-sftp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ziti/weewx-sftp?sort=semver)](https://github.com/ziti/weewx-sftp/releases)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

> A community-maintained fork of [matthewwall/weewx-sftp](https://github.com/matthewwall/weewx-sftp) (unmaintained). Copyright 2016-2026 Matthew Wall and contributors. Distributed under the terms of the GPLv3.

Report generator for WeeWX that uploads a local directory tree to a remote host
over SFTP. It is functionally equivalent to WeeWX's built-in FTP generator, but
uses the SSH file-transfer protocol.

The SFTP protocol is not the FTPS protocol! FTPS is handled by WeeWX's standard
FTP generator. This generator speaks SFTP via the
[Paramiko](https://www.paramiko.org/) SSH library.

Based on the FTP generator in WeeWX, with help from the SFTP generator
implemented by davies-barnard.

## Requirements

- WeeWX 5.0 or newer
- The `paramiko` Python module, installed into the same environment as WeeWX:

  ```
  pip install paramiko
  ```

## Installation

1. Install the extension straight from GitHub:

   ```
   weectl extension install https://github.com/ziti/weewx-sftp/archive/refs/heads/main.zip
   ```

   or from a downloaded release archive:

   ```
   weectl extension install weewx-sftp-x.y.zip
   ```

2. Add the SFTP settings to `weewx.conf`:

   ```
   [StdReport]
       [[SFTP]]
           skin = sftp
           enable = true
           user = username
           password = password
           server = host.example.com
           port = 22
           path = /weewx
   ```

3. Restart WeeWX:

   ```
   sudo systemctl restart weewx
   ```

## Options

| Option | Description |
| --- | --- |
| `user` | Remote username. Required. |
| `password` | Remote password. If it contains a comma or space, wrap it in double quotes. Omit when using key authentication. |
| `private_key` | Path to a private key file for key-based authentication. |
| `private_key_pass` | Passphrase for `private_key`, if it has one. |
| `server` | Hostname or IP address of the remote host. Required. |
| `port` | Port on the remote host. Default is `22`. |
| `path` | Destination directory on the remote host. Required. |
| `max_tries` | Connection and per-file upload attempts. Default is `3`. |

The local directory comes from the standard WeeWX report options `WEEWX_ROOT`
and/or `HTML_ROOT`; if unset here they are inherited from `[StdReport]`.

Host keys are not verified -- unknown keys are accepted automatically, matching
the original pysftp-based behaviour.

## Development

```
pip install -r requirements-dev.txt
ruff check .
pytest
```

Tag a commit `vX.Y` -- matching `VERSION` in `bin/user/sftp.py`, `version` in
`install.py`, and the top line of `changelog` -- and the release workflow builds
`weewx-sftp-X.Y.zip` and publishes it to GitHub Releases.
