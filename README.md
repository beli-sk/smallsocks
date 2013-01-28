smallSocks
==========

Small SOCKS server implementation in Python.

Project status
--------------

Currently supported features:

  * SOCKS4 and 4a protocols are supported
  * fork into background (daemon)
  * logging through syslog
  * reads config file

Limitations:

  * no access control
  * only *connect* command is supported, not *bind*

OS support
----------

Unix-like systems with Python and syslog.

Contact and support
-------------------

You can discuss smallSocks on the [mailing list](https://www.coders.sk/lists/listinfo/smallsocks).

Download
--------

### Release 0.1.0 alpha 1

Python source package:
[smallsocks-0.1.0a1.tar.gz](https://www.dropbox.com/s/13tmloe4dwsw5lv/smallsocks-0.1.0a1.tar.gz)

Debian/Ubuntu package:
[smallsocks_0.1.0a1-1_all.deb](https://www.dropbox.com/s/azfow7cu374pzb7/smallsocks_0.1.0a1-1_all.deb)
| [SHA1](https://www.dropbox.com/s/92seqekf491hj35/smallsocks_0.1.0a1-1_all.deb.sha1)
| [GPG sig](https://www.dropbox.com/s/14xdk3m2gpx0ta8/smallsocks_0.1.0a1-1_all.deb.sig)
| package source: [.dsc](https://www.dropbox.com/s/ci7i0cm3mmfqzr3/smallsocks_0.1.0a1-1.dsc)
| [.changes](https://www.dropbox.com/s/6ff0bdjxpdsos9b/smallsocks_0.1.0a1-1_amd64.changes)

License
-------

Copyright 2013 Michal Belica < devel *at* beli *dot* sk >

```
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/ .
```

