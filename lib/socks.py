#!/usr/bin/env/python
"""Socks server utility functions

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

import struct
import select
import socket
import logging
from pprint import pprint

logger = logging.getLogger('smallsocks')

class SocksError(Exception): pass
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

def socks_data_loop(sock, outsock, shutdown):
    while True:
        (rtr, rtw, err) = select.select([sock, outsock], [], [sock, outsock], 1)
        if shutdown.is_set(): break
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
    prio = logging.INFO if status else logging.WARNING
    logger.log(prio, "Connection from %s:%d to %s:%d by \"%s\" %s" % (
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
    addr, port = address
    if family != 0:       sfamily = family
    elif socket.has_ipv6: sfamily = socket.AF_INET6
    else:                 sfamily = socket.AF_INET
    pprint(address)
    ais = socket.getaddrinfo(addr, port, family, socket.SOCK_STREAM)
    s = socket.socket(sfamily, socket.SOCK_STREAM)
    s.settimeout(timeout)
    connected = False
    for ai in ais:
        (fam, st, pr, cn, sa) = ai
        logger.info("Trying address %s" % sa[0])
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

