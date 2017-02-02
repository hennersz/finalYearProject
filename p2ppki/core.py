#!/usr/bin/env python
# -*- coding: utf-8 -*-

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.protocol import Protocol
from twisted.python import log
from twisted.internet.protocol import Factory
from twisted.internet.endpoints import TCP4ServerEndpoint
from kademlia.network import Server

from storage import ListStorage
from dhtServer import DHTServer
from localServer import ControlServer

import sys

@inlineCallbacks
def initServer(localPort, remoteHost,remotePort):
    server = Server(storage=ListStorage())
    server.listen(localPort)
    yield server.bootstrap([(remoteHost, remotePort)])
    returnValue(server)

@inlineCallbacks
def init():
    server = yield initServer(8469, "127.0.0.1",8468)
    dht = DHTServer(server)
    controller = ControlServer(8007, dht)

if(__name__ == "__main__"):
    log.startLogging(sys.stdout)
    init()
    reactor.run()
