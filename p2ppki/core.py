#!/usr/bin/env python

from twisted.internet import reactor
from twisted.python import log
from kademlia.network import Server
import sys

log.startLogging(sys.stdout)

def quit(result):
    print "Key result: ", result
    reactor.stop()

def get(result, server):
    return server.get("a key").addCallback(quit)

def done(found, server):
    log.msg("Found nodes: %s" % found)
    return server.set("a key", "a value").addCallback(get, server)

server = Server()

server.listen(8468)
server.bootstrap([("192.168.62.128", 8468)]).addCallback(done, server)

reactor.run()
