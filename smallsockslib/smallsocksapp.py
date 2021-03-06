#!/usr/bin/env python

"""smallSocks application

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
import sys
import socket
import select
import signal
import logging
import threading
import SocketServer
import ConfigParser
from logging.handlers import SysLogHandler

from daemon import Daemon, PidFile
import socks

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
        prio = logging.WARNING
    elif t == socket.herror or t == socket.gaierror:
        etype = 'Resolver error'
        prio = logging.WARNING
    elif t == socks.Disconnect:
        etype = t.__name__
        prio = logging.INFO
    else:
        try:
            etype = t.__name__
        except:
            etype = t
        prio = logging.WARNING
    logger.log(prio, "%s: %s" % (etype, value))
    if exit:
        exit(1)

def sighandler(signum, frame):
    if signum == signal.SIGINT or signum == signal.SIGTERM:
        logger.info("received signal %d, shutting down" % signum)
        server.shutdown_event.set()

class ThreadTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True
    timeout = 1
    def handle_error(self, request, client_address):
        exception_handler()

class SocksTCPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        sock = self.request
        # read client request
        req = socks.recv_socks_request(sock)
        if req['ver'] != 4:
            raise socks.BadRequest("Unsupported protocol version %d" % req['ver'])
        elif req['cmd'] != 1:
            socks.send_socks_response(sock, False)
            raise socks.BadRequest("Unsupported command %d" % req['cmd'])
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
            conn = socks.create_connection((remaddr, req['port']), remfamily)
        except Exception:
            socks.log_request(self.client_address, req, False)
            socks.send_socks_response(sock, False)
            raise
        (outsock, remfamily, remaddr, remport) = conn
        socks.send_socks_response(sock, (remaddr, remport))
        socks.log_request(self.client_address, req)
        # pass data between sockets
        socks.socks_data_loop(sock, outsock, self.server.shutdown_event,
                self.server.xbuffer)

def server_process():
    signal.signal(signal.SIGINT, sighandler)
    signal.signal(signal.SIGTERM, sighandler)
    shutdown = threading.Event()
    shutdown.clear()
    server.shutdown_event = shutdown
    logger.info("smallSocks initialized, listening on %s port %d" % server.server_address)
    while not shutdown.is_set():
        try:
            server.handle_request()
        except select.error as e:
            if e[0] == 4:
                # select interrupted
                pass
            else:
                raise
    logger.info("smallSocks finished")

def run(CONFIGFILE, defaults):
    global logger
    global server

    config = ConfigParser.RawConfigParser(defaults)
    config.read(CONFIGFILE)

    logger = logging.getLogger('smallsocks')
    logger.setLevel(logging.DEBUG)
    handler = SysLogHandler(address=config.get('DEFAULT', 'syslog_socket'), facility=SysLogHandler.LOG_DAEMON)
    formatter = logging.Formatter('%(module)s[%(process)d][%(threadName)s] %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    HOST = config.get('DEFAULT', 'listen_address')
    PORT = config.getint('DEFAULT', 'listen_port')
    XBUFFER = config.getint('DEFAULT', 'buffer_size')

    try:
        USER = config.get('DEFAULT', 'user')
    except:
        USER = None
    try:
        GROUP = config.get('DEFAULT', 'group')
    except:
        GROUP = None

    try:
        server = ThreadTCPServer((HOST, PORT), SocksTCPHandler)
        server.xbuffer = XBUFFER
        daemon = Daemon(
            stdout=sys.stdout,
            stderr=sys.stderr,
            chdir=config.get('DEFAULT', 'working_directory'),
            user=USER,
            group=GROUP,
            )
        daemon.daemonize()
        with PidFile(config.get('DEFAULT', 'pid_file')):
            server_process()
    except:
        exception_handler()
        exit(1)
