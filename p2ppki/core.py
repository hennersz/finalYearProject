#!/usr/bin/env python

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.python import log
from kademlia.network import Server

from pisces.spkilib import keystore, spki

from storage import ListStorage
from dhtServer import DHTServer
from localServer import ControlServer
from certManager import CertManager
from verifier import Verifier

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
    h = spki.parseText('(hash md5 |aDuWZyd2NwEb25TZ/F3rng==|)')
    certs = CertManager(dht, keyStore)
    verifier = Verifier(certs, keyStore, '/Users/henrymortimer/.p2ppki/acl')
    names = verifier.identifiy(h)
    print names
    # certs.trust('Alice', 'me')
    # returnValue(ControlServer(8007, dht))


if(__name__ == "__main__"):
    log.startLogging(sys.stdout)
    init()
    reactor.run()
