# weewx-sftp

> Copyright 2016-2020 Matthew Wall, Distributed under terms of the GPLv3

Generator for weewx that uploads data using sftp.  Copy everything from a
designated local directory to a remote directory, using the sftp protocol.

This generator is intended to be functionally equivalent to the FTP generator
in weewx, but using a different protocol.

The sftp protocol is not the same as the ftps protocol!  The ftps protocol
is supported by the standard FTP generator in weewx.  This generator uses sftp,
which requires the pysftp module.

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

`user`, `password` - Username and password of the user.  If passord contains a comma or space then enclose it in double quotes.  Required.

`private_key` - Specify path to private key file for PKI authentication.

`private_key_pass` - Specify passphrase for private key file, if necessary.

`server` - The hostname or IP address of the remote host.  Required.
 
`port` - The port on the remote host.  Default is 22.

`path` - The path to the destination directory on the remote host.  Required.

The local directory is specified using the standard weeWX report options `WEEWX_ROOT` and/or `HTML_ROOT`.  If not specified, they are inherited from the values defined in `StdReport`.
