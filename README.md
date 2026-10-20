# weewx-sftp

> Copyright 2016-2020 Matthew Wall,  
> Copyright 2026 Sigi Meisenbichler,  
> Distributed under terms of the GPLv3

Generator for weewx that uploads data using sftp.  Copy everything from a
designated local directory to a remote directory, using the sftp protocol.

This generator is intended to be functionally equivalent to the FTP generator
in weewx, but using a different protocol.

The sftp protocol is not the same as the ftps protocol!  The ftps protocol
is supported by the standard FTP generator in weewx.  This generator uses sftp,
which requires the paramiko module.

Based on the FTP generator in weewx, with help from the SFTP generator
implemented by davies-barnard.

## Pre-requisites

This extension requires the `paramiko` python module.  It can be installed using
the system package manager such as `yum` or `apt`, or using `pip`.  Use the
appropriate installation method for your operating system and configuration!
For example, if you use `apt` then you can install it like this:

```
sudo apt install python3-paramiko
```

## Installation

1) Download and Install the generator

```
weectl extension install https://github.com/smeisens/weewx-sftp/archive/master.zip
```

2) Set the SFTP parameters in the weewx configuration file

```
[StdReport]
    [[SFTP]]
        skin = sftp
        user = username
        password = password
        server = host.example.com
        port = 2222
        path = /weewx
```

3) Re-start weewx

```
sudo systemctl restart weewx
```

## Options

`user` - Username on the remote host.  Required.

`password` - Password of the user.  If the password contains a comma or space then enclose it in double quotes.  Not needed when a private key is used.

`password_env` - Name of an environment variable holding the password.  If set, it is used instead of `password`, so the password does not have to be stored in `weewx.conf` (see below).

`private_key` - Path to a private key file for public key authentication.  RSA, ECDSA and Ed25519 keys are supported.

`private_key_pass` / `private_key_pass_env` - Passphrase for the private key, either directly or from an environment variable.

`server` - The hostname or IP address of the remote host.  Required.

`port` - The port on the remote host.  Default is 22.

`path` - The path to the destination directory on the remote host.  Required.

`known_hosts` - Path to an additional known_hosts file with the server's host key.  The weewx user's `~/.ssh/known_hosts` and `/etc/ssh/ssh_known_hosts` are always read.

`accept_new_host_key` - If `true`, an unknown host key is accepted once and saved to `known_hosts` (trust on first use, like OpenSSH `StrictHostKeyChecking=accept-new`).  A changed host key is always rejected.  Requires `known_hosts`.  Default is `false`.

`timeout` - Timeout in seconds for connecting and for network operations.  Default is 30.

`max_tries` - Number of attempts per file.  Default is 3.

The local directory is specified using the standard weeWX report options `WEEWX_ROOT` and/or `HTML_ROOT`.  If not specified, they are inherited from the values defined in `StdReport`.

## Security

### Host key verification

Since version 0.9 the server's host key is always verified.  Without a matching entry in a known_hosts file the upload is aborted with an error in the log.  This protects the password and the uploaded files against man-in-the-middle attacks.

Add the server's key once, as the user weewx runs as (`port` only if it is not 22):

```
ssh-keyscan -p 22 host.example.com | sudo tee /etc/weewx/sftp_known_hosts
```

Compare the printed fingerprints with the ones published by your provider, then set `known_hosts = /etc/weewx/sftp_known_hosts`.  Alternatively set `accept_new_host_key = true` together with `known_hosts` to store the key automatically on the first connection.

### Keeping the password out of weewx.conf

Put the password in a file that only root can read and let systemd pass it to weewx as an environment variable:

```
# /etc/weewx/sftp.env  (chown root:root, chmod 600)
WEEWX_SFTP_PASSWORD=secret
```

```
sudo systemctl edit weewx
```
```
[Service]
EnvironmentFile=/etc/weewx/sftp.env
```

Then use `password_env = WEEWX_SFTP_PASSWORD` instead of `password` and restart weewx.  Public key authentication without any password is even better, if your provider supports it.

### paramiko version

paramiko versions older than 3.4.0 are vulnerable to the Terrapin attack (CVE-2023-48795).  The extension logs a warning on every run when an older version is installed.  Debian 12 ships paramiko 2.12; install a newer version e.g. with `pip` or from backports.

### Upgrading from 0.8

The upload state is now stored as JSON (`#<report>.last.json`) instead of pickle.  The old state file is deleted without being read, so all files are uploaded once again after the upgrade.
