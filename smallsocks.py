#!/usr/bin/env python

import SocketServer
import struct

class ThreadTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

class Disconnect(Exception):
    pass

def recv_all(sock, length):
    """Receive a fixed number of bytes from socket, iteratively if needed"""
    data = ''
    l = 0
    while l < length:
        # gather required data from socket
        d = sock.recv(length - l)
        ld = len(d)
        if ld == 0:
            raise Disconnect
        data += d
        l += ld

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
    (i,) = struct.unpack('!'.data_types[len(data)], data)
    return i

def recv_socks_request(sock):
    data = recv_all(sock, 9)
    req = {
            'ver': bin2int(data[0:1]),
            'cmd': bin2int(data[1:2]),
            'port': bin2int(data[2:4]),
            'IP': socket.inet_ntoa(data[4:8]),
            }
    return req

class SocksTCPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        print "{} connected".format(self.client_address[0])
        req = recv_socks_request(self.request)
        pprint(req)
        while True:
            data = self.request.recv(1024)
            if len(data) == 0:
                print "{} disconnected".format(self.client_address[0])
                break
            print "{} wrote:".format(self.client_address[0])
            print data.strip()
            self.request.sendall(data.upper())

if __name__ == "__main__":
    HOST, PORT = "localhost", 1080
    server = ThreadTCPServer((HOST, PORT), SocksTCPHandler)
    server.serve_forever()
