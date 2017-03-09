#!/usr/bin/env python

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.python import log
from kademlia.network import Server

from pisces.spkilib import keystore

from storage import ListStorage
from dhtServer import DHTServer
from localServer import ControlServer
from certManager import CertManager

import sys


@inlineCallbacks
def initServer(localPort, remoteHost, remotePort):
    server = Server(storage=ListStorage())
    server.listen(localPort)
    yield server.bootstrap([(remoteHost, remotePort)])
    returnValue(server)


@inlineCallbacks
def init():
    server = yield initServer(8469, "127.0.0.1", 8468)
    dht = DHTServer(server)
    keyStore = keystore.KeyStore('/Users/henrymortimer/.p2ppki')
    certs = CertManager(dht, keyStore)
    certs.trust('Alice', 'me')
    returnValue(ControlServer(8007, dht))


if(__name__ == "__main__"):
    log.startLogging(sys.stdout)
    init()
    reactor.run()
