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
import sys

class Echo(Protocol):
    def dataReceived(self, data):
        print data

class EchoFactory(Factory):
    def buildProtocol(self, addr):
        return Echo()


@inlineCallbacks
def get(result, dht):
    value = yield dht.get("a key")
    print(value)

@inlineCallbacks
def done(found, server):
    dht = DHTServer(server)
    yield dht.set("a key", "value 1")
    yield dht.set("a key", "a value")
    value = yield dht.get("a key")
    print(value)

    #return server.set("a key", "a value").addCallback(get, server)

@inlineCallbacks
def initServer(localPort, remoteHost,remotePort):
    server = Server(storage=ListStorage())
    server.listen(localPort)
    server.bootstrap([(remoteHost, remotePort)])
    returnValue(server)
@inlineCallbacks
def init():
    server = yield initServer(8469, "127.0.0.1",8468)
    dht = DHTServer(server)
    endpoint = TCP4ServerEndpoint(reactor, 8007)
    endpoint.listen(EchoFactory(dht))

    reactor.run()

if(__name__ == "__main__"):
    log.startLogging(sys.stdout)
    init()

    reactor.run()
