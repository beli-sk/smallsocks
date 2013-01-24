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

import SocketServer
import struct
import socket
import select
import signal
from pprint import pprint

class ThreadTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True
    timeout = 1

class Disconnect(Exception):
    pass

def recv_strz(sock, maxlen = 65530):
    """Receive a zero terminated string on socket"""
    data = ''
    l = 0
    while l < maxlen:
        c = sock.recv(1)
        ld = len(c)
        if ld == 0:
            raise Disconnect()
        elif ld != 1:
            raise ValueError()
        elif ord(c) == 0:
            break
        data += d
        l += ld
    return data

def recv_all(sock, length):
    """Receive a fixed number of bytes from socket, iteratively if needed"""
    data = ''
    l = 0
    while l < length:
        d = sock.recv(length - l)
        ld = len(d)
        if ld == 0:
            raise Disconnect
        data += d
        l += ld
    return data

def bin2int(data):
    """Convert binary unsigned int to python integer

    Convert single raw unsigned int in network byte-order to python integer.
    Supported data lengths: 1, 2, 4, 8
    """
    data_types = {
            1: 'B',
            2: 'H',
            4: 'L',
            8: 'Q',
            }
    (i,) = struct.unpack('!' + data_types[len(data)], data)
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

class SocksTCPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        sock = self.request
        print "{} connected".format(self.client_address[0])
        req = recv_socks_request(sock)
        pprint(req)
        if req['ver'] != 4:
            print "%s unsupported protocol version detected %d" % \
                    (self.client_address[0], req['ver'])
            return
        elif req['cmd'] != 1:
            print "%s unsupported command %d" % \
                    (self.client_address[0], req['cmd'])
            send_socks_response(sock, False)
            return
        try:
            outsock = socket.create_connection((req['IP'], req['port']))
        except Exception as e:
            send_socks_response(sock, False)
            print "%s connect failed:" % (self.client_address[0])
            pprint(e)
            return
        send_socks_response(sock)
        while True:
            (rtr, rtw, err) = select.select([sock, outsock], [], [sock, outsock], 1)
            if shutdown: break
            for s in rtr:
                try:
                    data = s.recv(1024)
                except Exception as e:
                    print "%s receive failed:" % (self.client_address[0])
                    pprint(e)
                    return
                if len(data) == 0:
                    print "{} disconnected".format(self.client_address[0])
                    return
                if s == sock:
                    outsock.sendall(data)
                elif s == outsock:
                    sock.sendall(data)
                else:
                    print "Unknown socket found!"
                    return

shutdown = False

def sighandler(signum, frame):
    global shutdown
    if signum == signal.SIGINT or signum == signal.SIGTERM:
        shutdown = True

if __name__ == "__main__":
    HOST, PORT = "localhost", 1080
    server = ThreadTCPServer((HOST, PORT), SocksTCPHandler)
    signal.signal(signal.SIGINT, sighandler)
    #signal.signal(signal.SIGTERM, sighandler)
    while not shutdown:
        try:
            server.handle_request()
        except select.error as e:
            if e[0] == 4:
                print "handle_request interrupted"
            else:
                raise
