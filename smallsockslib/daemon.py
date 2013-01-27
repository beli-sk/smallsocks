#!/usr/bin/env python

"""Unix daemon tools module

Copyright 2013 Michal Belica <devel@beli.sk>

This file is part of smallSocks.

smallSocks is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

smallSocks is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with smallSocks.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import pwd
import grp
import sys
import fcntl
import resource

class DaemonError(Exception):
    pass

def redirect_stream(system_stream, target_stream):
    """Redirect a system stream to a specified file.

    `system_stream` is a standard system stream such as
    ``sys.stdout``. `target_stream` is an open file object that
    should replace the corresponding system stream object.

    If `target_stream` is ``None``, defaults to opening the
    operating system's null device and using its file descriptor.

    Taken from python-daemon http://pypi.python.org/pypi/python-daemon/
    """

    if target_stream is None:
        target_fd = os.open(os.devnull, os.O_RDWR)
    else:
        target_fd = target_stream.fileno()
    os.dup2(target_fd, system_stream.fileno())

class Daemon():
    def __init__(self, chroot=None, chdir='/', user=None, group=None,
            stdin=None, stdout=None, stderr=None):
        """Create a configured daemonizer instance"""
        self.chroot = chroot
        self.chdir = chdir
        # try to convert user and group to integer
        # if specified as integer in a string
        try:
            user = int(user)
        except:
            pass
        try:
            group = int(group)
        except:
            pass

        pwent = None
        if type(user) is str or type(user) is unicode:
            # user field contains a user name
            pwent = pwd.getpwnam(user)
            self.uid = pwent.pw_uid
        else:
            # or user ID
            self.uid = user
        if type(group) is str or type(group) is unicode:
            # group field contains a group name
            self.gid = grp.getgrnam(group).gr_gid
        else:
            # or group ID
            self.gid = group

        if self.uid is not None and self.gid is None:
            # use user's default group if a user is specified and group is not
            if not pwent:
                pwent = pwd.getpwuid(self.uid)
            self.gid = pwent.pw_gid
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr

    def daemonize(self):
        """Daemonize
        
        We do not close open files, this is left as an excercise to
        the user, to clean up all his open files before calling us.
        """

        # prevent core dumps
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        # change umask
        os.umask(0)

        # redirect stdio
        redirect_stream(sys.stdin, self.stdin)
        redirect_stream(sys.stdout, self.stdout)
        redirect_stream(sys.stderr, self.stderr)

        # chroot
        if self.chroot:
            os.chroot(self.chroot)
            os.chdir('/')

        # change to working directory
        if self.chdir:
            os.chdir(self.chdir)

        # set user/group ID
        if self.gid is not None:
            os.setgid(self.gid)
        if self.uid is not None:
            os.setuid(self.uid)

        # detach process if not started by init
        if os.getppid() != 1:
            pid = os.fork()
            if pid != 0:
                os._exit(0)
            os.setsid()
            pid = os.fork()
            if pid != 0:
                os._exit(0)

class PidFile():
    """Context manager that locks a pid file.  Implemented as class
    not generator because daemon.py is calling .__exit__() with no parameters
    instead of the None, None, None specified by PEP-343."""
    # pylint: disable=R0903

    def __init__(self, path):
        self.path = path
        self.pidfile = None

    def __enter__(self):
        pidfd = os.open(self.path, os.O_CREAT|os.O_RDWR, 0600)
        self.pidfile = os.fdopen(pidfd, "a+")
        try:
            fcntl.flock(self.pidfile.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            raise SystemExit("Already running according to " + self.path)
        self.pidfile.seek(0)
        self.pidfile.truncate()
        self.pidfile.write(str(os.getpid()))
        self.pidfile.flush()
        self.pidfile.seek(0)
        return self.pidfile

    def __exit__(self, exc_type=None, exc_value=None, exc_tb=None):
        try:
            self.pidfile.close()
        except IOError as err:
            # ok if file was just closed elsewhere
            if err.errno != 9:
                raise
        os.remove(self.path)

