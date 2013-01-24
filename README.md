smallSocks
==========

Small SOCKS server implementation in Python.

Project status
--------------

These are the current features and limitations:

  * SOCKS4 protocol is supported
  * only *connect* command is supported, not *bind*
  * fork into background (daemon)
  * logging through syslog
  * listens on `localhost`, port *1080*
  * no access control

OS support
----------

Unix-like systems with Python and syslog.

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

