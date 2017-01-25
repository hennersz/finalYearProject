#! /usr/bin/env python

"""A Yarrow daemon.

Simple protocol for requesting random bytes over a socket.  The client
requests random data by sending a 32-bit int in network byte-order.
The server will return that many bytes of random data.  The return
format is a 32-bit in in network byte order, specifying length of
return value, followed by that many bytes of data.  The client can
issue multiple requests on a single socket.
"""

from pisces import yarrow

import socket
import struct
import sys
from SocketServer import ThreadingTCPServer, BaseRequestHandler

DEFAULT_PORT = 12000

class YarrowServer(ThreadingTCPServer):
    super_init = ThreadingTCPServer.__init__
    
    def __init__(self, cprng, serverAddress, handlerClass):
        self.super_init(serverAddress, handlerClass)
        self.cprng = cprng

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET,
                               socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)

class RequestHandler(BaseRequestHandler):
    def handle(self):
        while 1:
            buf = self.request.recv(4)
            if buf == '':
                break
            reqBytes = struct.unpack('!i', buf)[0]
            buf = self.server.cprng.getOutput(reqBytes)
            respBytes = struct.pack('!i', len(buf))
            self.request.send('%s%s' % (respBytes, buf))

def startYarrow(fast_sources, slow_sources, klass=None):
    """Create a Yarrow object and two threads to poll the system"""
    if klass is None:
        cprng = yarrow.Yarrow()
    else:
        cprng = klass()
    poll_fast = yarrow.EntropyGatherer(fast_sources, cprng)
    poll_slow = yarrow.EntropyGatherer(slow_sources, cprng)
    poll_fast.start()
    poll_slow.start()
    return cprng

# A variety of sources that work on Solaris.  The entropy estimates
# are probably total nonsense.   Format for these lists is:
#       (command,   freq,  entropy)
if sys.platform == 'linux2':
    fast_sources = [
        ("uptime",      5, 2),
        ("netstat -in", 5, 2),
        ("df",          5, 6),
        ("netstat -s",  5, 16),
        ("vmstat -n 1 2",
                        5, 8),
        ("head --bytes 8 /dev/random",
                        5, 32),
        ]

    slow_sources = [
        ("netstat -n", 60, 34),
        ("w",          60, 12),
        ("ps aux",     60, 64),
        ("last -50",   60, 12),
        ("/sbin/arp -a",
                       60, 8),
        ("head --bytes 32 /dev/random",
                       60, 96),
        ("cat /proc/stat", 5, 16),
        ]

elif sys.platform == 'sunos5':
    fast_sources = [
        ("uptime",      5, 2),
        ("netstat -m",  5, 8),
        ("netstat -in", 5, 2),
        ("df",          5, 6),
        ("netstat -s",  5, 16),
        ("vmstat -s",   5, 32),
        ("ipcs -a",     5, 1),
        ]

    slow_sources = [
        ("netstat -n", 60, 34),
        ("w",          60, 12),
        ("ps -elf",    60, 64),
        ("last -50",   60, 12),
        ("arp -a",     60, 8),
        ("iostat -x",  60, 23),
        ("vmstat",     60, 7),
        ]
# for other systems, try something like the commands above

def main(host, port):
    cprng = startYarrow(fast_sources, slow_sources,
                        yarrow.ThreadedYarrow)  
    server = YarrowServer(cprng, (host, port), RequestHandler)
    server.serve_forever()

if __name__ == "__main__":
    import sys
    import getopt
    host = socket.gethostname()
    port = DEFAULT_PORT
    opts, args = getopt.getopt(sys.argv[1:], 'h:p:')
    for k, v in opts:
        if k == '-h':
            host = v
        elif k == '-p':
            port = int(v)
    main(host, port)
