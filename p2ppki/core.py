#!/usr/bin/env python

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.python import log
from twisted.python.logfile import DailyLogFile
from kademlia.network import Server

from pisces.spkilib import keystore, spki

from storage import ListStorage
from dhtServer import DHTServer
from localServer import ControlServer
from certManager import CertManager
from verifier import Verifier
from config import Config

import sys
from os import path


@inlineCallbacks
def initServer(localPort, remoteHost, remotePort):
    server = Server(storage=ListStorage())
    server.listen(localPort)
    yield server.bootstrap([(remoteHost, remotePort)])
    returnValue(server)


@inlineCallbacks
def init(conf):
    logFile = DailyLogFile.fromFullPath(path.join(conf['dataDir'], 'logs/server.log'))
    log.startLogging(logFile, setStdout=0)
    server = yield initServer(8469, "127.0.0.1", 8468)
    dht = DHTServer(server)
    keyStore = keystore.KeyStore(conf['dataDir'])
    certs = CertManager(dht, keyStore)
    verifier = Verifier(certs, keyStore, path.join(conf['dataDir'], 'acl'))
    returnValue(ControlServer(8007, dht))


if(__name__ == "__main__"):
    conf = Config('~/.p2ppki/config.cfg')
    init(conf)
    reactor.run()
