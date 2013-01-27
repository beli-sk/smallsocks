smallSocks - installation
=========================

Install and configure
---------------------

1. Run the setup, it will install the program files onto your system:

    python setup.py install

2. Edit the configuration file /etc/smallsocks.conf to your taste. It should
be well self-documented.

Start-up scripts
----------------

If you are using Debian, Ubuntu or other distribution with Upstart, you can
use the provided upstart job config file.

1. Install the job configuration file and the defaults file from the unpacked source archive:

    cp init/smallsocks.conf /etc/init/smallsocks.conf
    cp init/smallsocks.default /etc/default/smallsocks

2. Enable the upstart job by editing the file /etc/default/smallsocks and
changing the line `server_run=false` to `server_run=true`.

If you would create start-up scripts for other distributions, please share
them with other users by sending them either as pull request on GitHub,
or by email to the address of the mailing list [smallsocks@coders.sk] .
