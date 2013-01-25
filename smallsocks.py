#!/usr/bin/env python
"""smallSocks

Copyright 2013 Michal Belica <devel@beli.sk>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/.
"""

HOST, PORT = "localhost", 1080
PIDFILE = '/smallsocks.pid'
CHROOT = '/var/empty'
WORKDIR = '/' # inside chroot, if CHROOT is set

import os
import sys
import fcntl
import struct
import socket
import select
import signal
import daemon
import SocketServer
from syslog import syslog, openlog, LOG_DEBUG, LOG_INFO, LOG_NOTICE, \
        LOG_WARNING, LOG_ERR, LOG_PID, LOG_DAEMON

class PidFile(object):
    """Context manager that locks a pid file.  Implemented as class
    not generator because daemon.py is calling .__exit__() with no parameters
    instead of the None, None, None specified by PEP-343."""
    # pylint: disable=R0903

    def __init__(self, path):
        self.path = path
        self.pidfile = None

    def __enter__(self):
        self.pidfile = open(self.path, "a+")
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

class SocksError(Exception):
    def __init__(self, value = None):
        self.value = value
    def __str__(self):
        return self.value

class Disconnect(SocksError): pass
class BadRequest(SocksError): pass

def exception_handler(t=None, value=None, traceback=None):
    """Handle exceptions politely (with syslog)"""
    del traceback
    if not t:
        exit = False
        (t, value) = sys.exc_info()[:2]
    else:
        exit = True
    if t == socket.error:
        etype = 'Socket error'
        prio = LOG_WARNING
    elif t == socket.herror or t == socket.gaierror:
        etype = 'Resolver error'
        prio = LOG_WARNING
    elif t == Disconnect:
        etype = t.__name__
        prio = LOG_INFO
    else:
        try:
            etype = t.__name__
        except:
            etype = t
        prio = LOG_WARNING
    syslog(prio, "%s: %s" % (etype, value))
    if exit:
        exit(1)

class ThreadTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True
    timeout = 1
    def handle_error(self, request, client_address):
        exception_handler()

def recv_strz(sock, maxlen = 65530):
    """Receive a zero terminated string on socket
    
    Raises Disconnect, ValueError or Exception on weird errors"""
    data = ''
    l = 0
    while True:
        c = sock.recv(1)
        ld = len(c)
        if ld == 0:
            raise Disconnect('Client disconnected')
        elif ld != 1:
            raise Exception('Long read on socket')
        elif ord(c) == 0:
            break
        data += c
        l += ld
        if l > maxlen:
            raise ValueError('String too long')
    return data

def recv_all(sock, length):
    """Receive a fixed number of bytes from socket, iteratively if needed
    
    Raises Disconnect"""
    data = ''
    l = 0
    while l < length:
        d = sock.recv(length - l)
        ld = len(d)
        if ld == 0:
            raise Disconnect('Client disconnected')
        data += d
        l += ld
    return data

def bin2int(data):
    """Convert binary unsigned int to python integer
    
    Convert single raw unsigned int in network byte-order to python integer.
    Supported data lengths: 1, 2, 4, 8
    
    Raises ValueError on non-standard data length
    """
    data_types = {
            1: 'B',
            2: 'H',
            4: 'L',
            8: 'Q',
            }
    try:
        (i,) = struct.unpack('!' + data_types[len(data)], data)
    except KeyError:
        raise ValueError('Raw integer of non-standard length')
    return i

def recv_socks_request(sock):
    """Receive SOCKS4 request on socket and return it's details"""
    data = recv_all(sock, 8)
    req = {
            'ver': bin2int(data[0:1]),
            'cmd': bin2int(data[1:2]),
            'port': bin2int(data[2:4]),
            'user': recv_strz(sock, 254),
            }
    # check for SOCKS4a request (IP looks like 0.0.0.x, x > 0)
    ipint = bin2int(data[4:8])
    if req['ver'] == 4 and ipint > 0 and ipint < 256:
        # SOCKS4a
        req['host'] = recv_strz(sock, 253)
    else:
        req['IP'] = socket.inet_ntoa(data[4:8])
        
    return req

def send_socks_response(sock, status=True, address=None):
    data = struct.pack('!BB', 0, 0x5a if status else 0x5b)
    if address:
        data += struct.pack('!H', address[1])
        data += socket.inet_aton(address[0])
    else:
        data += struct.pack('!HL', 0, 0)
    sock.sendall(data)

def socks_data_loop(sock, outsock):
    while True:
        (rtr, rtw, err) = select.select([sock, outsock], [], [sock, outsock], 1)
        if shutdown: break
        for s in rtr:
            if s == sock:
                direction = 1 # from client to remote
            elif s == outsock:
                direction = 2 # from remote to client
            else:
                raise Exception("Unknown socket found in loop!")
            data = s.recv(1024)
            if len(data) == 0:
                if direction == 1:
                    raise Disconnect('Client disconnected')
                else:
                    raise Disconnect('Remote end disconnected')
            if direction == 1:
                outsock.sendall(data)
            else:
                sock.sendall(data)

def log_request(address, req, status = True):
    prio = LOG_NOTICE if status else LOG_WARNING
    syslog(prio, "Connection from %s:%d to %s:%d by \"%s\" %s" % (
            address[0], address[1],
            req['IP'] if 'IP' in req else req['host'], req['port'],
            req['user'],
            'succeeded' if status else 'failed'
            ))

def create_connection(address, family=0, timeout=5):
    """Create a TCP connection

    Takes address as a tuple of (host,port), resolves host and connects to all
    possible addresses until one succeeds. Addresses can be limited
    by specifying family.

    Returns (socket, family, addr, port)
    """
    addr,port = address
    if family != 0:       sfamily = family
    elif socket.has_ipv6: sfamily = socket.AF_INET6
    else:                 sfamily = socket.AF_INET
    ais = socket.getaddrinfo(addr, port, family, socket.SOCK_STREAM)
    s = socket.socket(sfamily, socket.SOCK_STREAM)
    s.settimeout(timeout)
    connected = False
    for ai in ais:
        (fam, st, pr, cn, sa) = ai
        syslog(LOG_INFO, "Trying address %s" % sa[0])
        try:
            s.connect(sa)
        except Exception as e:
            exc = e
        else:
            connected = True
            break
    if connected:
        return (s,fam) + sa
    else:
        raise exc # Exception from last connect attempt

class SocksTCPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        sock = self.request
        # read client request
        req = recv_socks_request(sock)
        if req['ver'] != 4:
            raise BadRequest("Unsupported protocol version %d" % req['ver'])
        elif req['cmd'] != 1:
            send_socks_response(sock, False)
            raise BadRequest("Unsupported command %d" % req['cmd'])
        if 'IP' in req:
            remaddr = req['IP']
        else:
            remaddr = req['host']
        if req['ver'] == 4:
            remfamily = socket.AF_INET
        else:
            remfamily = 0 # any family
        # create requested outgoing connection
        try:
            conn = create_connection((remaddr, req['port']), remfamily)
        except Exception:
            log_request(self.client_address, req, False)
            send_socks_response(sock, False)
            raise
        (outsock, remfamily, remaddr, remport) = conn
        send_socks_response(sock, (remaddr, remport))
        log_request(self.client_address, req)
        # pass data between sockets
        socks_data_loop(sock, outsock)

def sighandler(signum, frame):
    global shutdown
    if signum == signal.SIGINT or signum == signal.SIGTERM:
        syslog(LOG_NOTICE, "received signal %d, shutting down" % signum)
        shutdown = True

def server_process():
    global shutdown
    global server
    global devnull
    shutdown = False
    signal.signal(signal.SIGINT, sighandler)
    signal.signal(signal.SIGTERM, sighandler)
    syslog(LOG_NOTICE, "smallSocks initialized, listening on %s port %d" % (HOST, PORT))
    # redirect stdout/err to /dev/null after initialization complete
    daemon.daemon.redirect_stream(sys.stdout, devnull)
    daemon.daemon.redirect_stream(sys.stderr, devnull)
    while not shutdown:
        try:
            server.handle_request()
        except select.error as e:
            if e[0] == 4:
                # select interrupted
                pass
            else:
                raise
    syslog(LOG_NOTICE, "smallSocks finished")

if __name__ == "__main__":
    openlog(ident='smallsocks', logoption=LOG_PID, facility=LOG_DAEMON)
    try:
        server = ThreadTCPServer((HOST, PORT), SocksTCPHandler)
    except:
        exception_handler()
        exit(1)
    devnull = open(os.devnull, "r+")
    with daemon.DaemonContext(
            # when following is commented, redirects stdout/err to /dev/null
            stdin=devnull,
            stdout=sys.stdout,
            stderr=sys.stderr,
            files_preserve=[server] + range(10),
            pidfile=PidFile(PIDFILE),
            chroot_directory=CHROOT,
            working_directory=WORKDIR,
            ) as context:
        server_process()
