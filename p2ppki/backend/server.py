#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
.. module:: server
    :platform: UNIX
    :synopsis: Initialises and runs server.

.. moduleauthor:: Henry Mortimer <henry@morti.net>

"""

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.python import log
from twisted.python.logfile import DailyLogFile
from kademlia.network import Server

from pisces.spkilib import keystore

from storage import ListStorage
from dhtServer import DHTServer
from localServer import ControlServer
from certManager import CertManager
from keyManager import KeyManager
from verifier import Verifier
from ..config import Config

from os import path


@inlineCallbacks
def initServer(localPort, remoteHost, remotePort):
    """Initialises the DHT and connects it to the 
    bootstrapping server.

    Args:
        localPort: Int.

        remoteHost: String - Must be ip address not 
        domain name.

        remotePort: Int.

    Returns:
        Kademlia Server object.
    """

    server = Server(storage=ListStorage())
    server.listen(localPort)
    yield server.bootstrap([(remoteHost, remotePort)])
    returnValue(server)


@inlineCallbacks
def init(conf):
    """Creates all the required object to run the program

    Args:
        conf: Config object.

    Returns:
        ControlServer object.
    """
    # Setup logger
    logPath = path.join(conf['dataDir'], 'logs/server.log')
    logFile = DailyLogFile.fromFullPath(logPath)
    log.startLogging(logFile)

    # Create DHT Server
    server = yield initServer(conf['serverPort'], conf['bootStrapServer'], 8468)
    dht = DHTServer(server)

    # Create key and cert management objects
    keyStore = keystore.KeyStore(conf['dataDir'])
    keys = KeyManager(dht, keyStore)
    certs = CertManager(dht, keyStore)
    aclDir = path.join(conf['dataDir'], 'acl')
    verifier = Verifier(certs, keyStore, aclDir, conf["searchDepth"])

    # Return value so it doesn't get garbage collected
    returnValue(ControlServer(conf['localPort'], dht, keys, certs, verifier, keyStore, reactor))


def runServer():
    """Start program."""
    conf = Config('~/.p2ppki/config.cfg')
    init(conf)
    reactor.run()
