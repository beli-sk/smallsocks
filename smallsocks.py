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

import sys
import SocketServer
import struct
import socket
import select
import signal
from pprint import pprint

class ThreadTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True
    timeout = 1
    def handle_error(self, request, client_address):
        """Handle exceptions politely"""
        (t, value) = sys.exc_info()[:2]
        if t == socket.error:
            etype = 'Socket error'
        elif t == socket.herror or t == socket.gaierror:
            etype = 'Resolver error'
        else:
            etype = t.__name__
        print "%s: %s" % (etype, value)

class SocksError(Exception):
    def __init__(self, value = None):
        self.value = value
    def __str__(self):
        return self.value
    def __repr__(self):
        return self.__str__()

class Disconnect(SocksError): pass
class BadRequest(SocksError): pass

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
        data += d
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
            'IP': socket.inet_ntoa(data[4:8]),
            'user': recv_strz(sock, 254)
            }
    return req

def send_socks_response(sock, status = True):
    data = struct.pack('!BBHL', 0, 0x5a if status else 0x5b, 0, 0)
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
    print "Connection from %s:%d to %s:%d by \"%s\" %s" % (
            address[0], address[1],
            req['IP'], req['port'],
            req['user'],
            'succeeded' if status else 'failed'
            )

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
        # create requested outgoing connection
        try:
            outsock = socket.create_connection((req['IP'], req['port']))
        except Exception:
            log_request(self.client_address, req, False)
            send_socks_response(sock, False)
            raise
        send_socks_response(sock)
        log_request(self.client_address, req)
        # pass data between sockets
        socks_data_loop(sock, outsock)

def sighandler(signum, frame):
    global shutdown
    if signum == signal.SIGINT or signum == signal.SIGTERM:
        print "received signal %d, shutting down" % signum
        shutdown = True

if __name__ == "__main__":
    global shutdown
    shutdown = False
    HOST, PORT = "localhost", 1080
    server = ThreadTCPServer((HOST, PORT), SocksTCPHandler)
    signal.signal(signal.SIGINT, sighandler)
    signal.signal(signal.SIGTERM, sighandler)
    print "smallSocks initialized, listening on %s port %d" % (HOST, PORT)
    while not shutdown:
        try:
            server.handle_request()
        except select.error as e:
            if e[0] == 4:
                # select interrupted
                pass
            else:
                raise
    print "smallSocks finished"
