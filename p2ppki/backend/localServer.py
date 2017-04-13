#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
.. module:: localServer
    :platform: UNIX
    :synopsis: Server that clients can connect to, to interface with the rest of the program.

.. moduleauthor:: Henry Mortimer <henry@morti.net>

"""

from twisted.protocols.basic import LineReceiver
from twisted.internet.protocol import Factory
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.defer import inlineCallbacks, returnValue

from distutils.util import strtobool
from ..utils import parseKeyIdInput, hashToB64


class ControlProtocol(LineReceiver):
    """Extends a twisted LineReceiver to create
    a contorl protocol.
    """

    supportedCommands = ['GET', 'SET', 'LIST', 'NAME',
                         'TRUST', 'TRUSTCA', 'IDENTIFY', 'STOP']

    def connectionMade(self):
        """Sends a response to clients up connection"""

        self.sendLine("Connected")

    def lineReceived(self, line):
        """Splits line on spaces and identifies
        the appropriate command.
        From LineReceiver.

        Args:
            line: String.
        """
        data = line.split()
        command = data[0].upper()

        args = data[1:]
        if command == 'GET':
            self.handleGet(args)
        elif command == 'SET':
            self.handleSet(args)
        elif command == 'LIST':
            self.handleList(args)
        elif command == 'NAME':
            self.name(args)
        elif command == 'TRUST':
            self.trust(args)
        elif command == 'TRUSTCA':
            self.trustCA(args)
        elif command == 'IDENTIFY':
            self.identify(args)
        elif command == 'STOP':
            self.stopServer()
        else:
            self.handleUnknown(data[0])

    def handleList(self, args):
        """Sends hashes of local keys to client
         
         Args:
            args: [String]

        Returns:
            None
        """
        usage = "LIST usage: LIST [True|False]"
        if len(args) > 1:
            self.sendLine(usage)
            return
        elif len(args) == 1:
            try:
                listPriv = strtobool(args[0])
            except ValueError:
                self.sendLine(usage)
                return
        else:
            listPriv = False

        pub, priv = self.factory.keys.listLocalKeys(listPriv)
        if pub is not None:
            self.sendLine("Public:")
            for key in pub:
                self.sendLine(str(key.getPrincipal()))

        if priv is not None:
            self.sendLine("Private")
            for key in priv:
                self.sendLine(str(key))

        if pub is None and priv is None:
            self.sendLine("No keys found")

    def handleGet(self, args):
        """Parses get command and delegates
        to key or cert function

        Args:
            args: [String]

        Returns:
            None
        """

        usage = "GET usage: GET [KEY|CERTS]"
        if(len(args) < 2):
            self.sendLine(usage)
            return None

        cmd = args[0].upper()

        if cmd == 'KEY':
            self.getKey(args[1:])
        elif cmd == 'CERTS':
            self.getCerts(args[1:])
        else:
            self.sendLine(usage)

    def handleSet(self, args):
        """Parses set command and delegates
        to key or cert function

        Args:
            args: [String]

        Returns:
            None
        """

        usage = "SET usage: SET [KEY|CERTS] <args>"
        if(len(args) < 2):
            self.sendLine(usage)
            return None

        cmd = args[0].upper()

        if cmd == 'KEY':
            self.setKey(args[1:])
        elif cmd == 'CERTS':
            self.setCerts(args[1:])
        else:
            self.sendLine(usage)

    @inlineCallbacks
    def setKey(self, args):
        """Set a key in the DHT

        Args:
            args: [String]

        Returns:
            None
        """

        usage = "SET KEY usage: SET KEY <keyId>"

        if len(args) != 1:
            self.sendLine(usage)
            returnValue(None)

        try:
            keyHash = parseKeyIdInput(args[0], self.factory.keystore)
        except (NameError, ValueError), e:
            self.sendLine(str(e))
            returnValue(None)

        try:
            ret = yield self.factory.keys.insertKey(keyHash)
        except ValueError, e:
            self.sendLine(str(e))
            returnValue(None)

        if ret:
            self.sendLine("Successfully set key in dht")
        else:
            self.sendLine("Failed to set key in dht")

    @inlineCallbacks
    def getKey(self, args):
        """Gets a key from the DHT and stores
        it locally.

        Args:
            args: [String]

        Returns:
            None
        """

        usage = "GET KEY <keyHash>"

        if len(args) != 1:
            self.sendLine(usage)
            returnValue(None)

        try:
            keyHash = parseKeyIdInput(args[0],
                                      self.factory.keystore,
                                      parseName=False)
        except ValueError:
            keyHash = args[0]

        key = yield self.factory.keys.getKey(keyHash)

        if key is None:
            self.sendLine("No key found for hash %s" % args[0])
        elif isinstance(key, list):
            self.sendLine('Found %d keys, for %s. They should be identified before use' % (len(key), keyHash))
            for k in key:
                self.sendLine('Found %s' % hashToB64(k.getPrincipal()))
                self.factory.keystore.addPublicKey(k)
            self.factory.keystore.save()
        else:
            self.factory.keystore.addPublicKey(key)
            self.factory.keystore.save()
            self.sendLine("Successfully retrieved key for hash %s" % args[0])

    @inlineCallbacks
    def getCerts(self, args):
        """Gets certificates from certifcates 
        and stores them locally

        Args:
            args: [String]

        Returns:
            None
        """

        usage = "GET CERTS <subjectId>"

        if len(args) != 1:
            self.sendLine(usage)
            returnValue(None)

        try:
            keyHash = parseKeyIdInput(args[0], self.factory.keystore)
        except (NameError, ValueError), e:
            self.sendLine(str(e))
            returnValue(None)

        certs = yield self.factory.certs.getCertificates(keyHash)
        if certs == [] or certs is None:
            self.sendLine("No certificates found for %s" % args[0])
            returnValue(None)

        self.sendLine("Found %d certificates" % len(certs))
        for cert in certs:
            self.factory.keystore.addCert(cert)
        returnValue(None)

    @inlineCallbacks
    def setCerts(self, args):
        """Sets all local certs in the dht for 
        a subject.

        Args:
            args: [String]

        Returns:
            None
        """
        usage = "SET CERTS <subjId>"

        if len(args) != 1:
            self.sendLine(usage)
            returnValue(None)

        try:
            keyHash = parseKeyIdInput(args[0], self.factory.keystore)
        except (NameError, ValueError), e:
            self.sendLine(str(e))
            returnValue(None)

        certs = self.factory.keystore.lookupCertBySubject(keyHash)

        if certs == []:
            self.sendLine("No certs found for %s" % args[0])
            returnValue(None)

        for cert in certs:
            res = yield self.factory.certs.storeCert(cert)
            if not res:
                self.sendLine("A certificate failed to insert")

    @inlineCallbacks
    def name(self, args):
        """Generates a name certificate for a key 
        and stores it in the DHT.

        Args:
            args: [String]

        Returns:
            None
        """

        usage = "NAME <subjectHash> <name> [issuerId]"

        if len(args) < 2:
            self.sendLine(usage)
            returnValue(None)
        elif len(args) > 3:
            self.sendLine(usage)
            returnValue(None)

        try:
            subjHash = parseKeyIdInput(args[0],
                                       self.factory.keystore,
                                       parseName=False)
        except ValueError, e:
            self.sendLine(str(e))
            returnValue(None)

        if len(args) == 3:
            try:
                issuerHash = parseKeyIdInput(args[2], self.factory.keystore)
            except (NameError, ValueError), e:
                self.sendLine(str(e))
                returnValue(None)
        else:
            issuerHash = None

        ret = yield self.factory.certs.name(subjHash, args[1], issuerHash)
        if ret:
            self.sendLine("Successful")
        else:
            self.sendLine("Failed")

    @inlineCallbacks
    def trust(self, args):
        """Creates a trust certificate and
        stores it locally.

        Args:
            args: [String]

        Returns:
            None
        """

        usage = "TRUST <subjectId>"

        if len(args) != 1:
            self.sendLine(usage)
            returnValue(None)

        try:
            subjHash = parseKeyIdInput(args[0], self.factory.keystore)
        except (NameError, ValueError), e:
            self.sendLine(str(e))
            returnValue(None)

        yield self.factory.certs.trust(subjHash)
        self.sendLine("Done!")

    @inlineCallbacks
    def trustCA(self, args):
        """Creates a CA certificate and stores 
        it in the DHT and locally.

        Args:
            args: [String]

        Returns:
            None
        """

        usage = "TRUSTCA  <subjectId> <delegate> [issuerId]"

        if len(args) < 2:
            self.sendLine(usage)
            returnValue(None)
        elif len(args) > 3:
            self.sendLine(usage)
            returnValue(None)

        try:
            subjHash = parseKeyIdInput(args[0], self.factory.keystore)
        except (NameError, ValueError), e:
            self.sendLine(str(e))
            returnValue(None)

        try:
            delegate = strtobool(args[1])
        except ValueError:
            self.sendLine(usage)
            returnValue(None)

        if len(args) == 3:
            try:
                issuerHash = parseKeyIdInput(args[2], self.factory.keystore)
            except (NameError, ValueError), e:
                self.sendLine(str(e))
                returnValue(None)
        else:
            issuerHash = None

        yield self.factory.certs.addCA(subjHash, delegate, issuerHash)
        self.sendLine("Done!")

    @inlineCallbacks
    def identify(self, args):
        """Attempts to find certified 
        name for a key. 

        Args:
            args: [String]

        Returns:
            None
        """

        usage = "IDENTIFY <keyHash>"

        if len(args) != 1:
            self.sendLine(usage)
            returnValue(None)

        try:
            subjHash = parseKeyIdInput(args[0],
                                       self.factory.keystore,
                                       parseName=False)
        except ValueError, e:
            self.sendLine(str(e))
            returnValue(None)

        names = yield self.factory.verifier.identify(subjHash)

        if names == []:
            self.sendLine("Could not identify hash %s" % args[0])
            returnValue(None)
        self.sendLine("Found these names:")
        for name in names:
            self.sendLine(name)

    def stopServer(self):
        """Stops the server from running."""
        self.factory.keystore.close()
        self.factory.reactor.stop()

    def handleUnknown(self, command):
        """Creates response for unknown commands

        Args:
            command: String

        Returns:
            None
        """

        self.sendLine("Unknown command: %s" % (command))
        self.sendLine("Supported commands: %s" % (str(self.supportedCommands)))


class ControlFactory(Factory):
    """Extends the twisted protocol factory 
    to create a control protocol
    """

    protocol = ControlProtocol

    def __init__(self, dht, keys, certs, verifier, keystore, reactor):
        """Initialises factory

        Args:
            dht: dhtServer.DHTServer object.

            keys: keyManager.Keymanager object.
            
            certs: certManager.CertManager object.

            verifier: verifier.Verifier object.

            keystore: pisces KeyStore object.

            reactor: twisted reactor.
        """

        self.dht = dht
        self.keys = keys
        self.certs = certs
        self.verifier = verifier
        self.keystore = keystore
        self.reactor = reactor


class ControlServer(object):
    """Creates a ControlFactory and binds
    it to a local port.
    """

    def __init__(self, port, dht, keys, certs, verifier, keystore, reactor):
        """Init server object

        Args:
            port: Int.

            dht: dhtServer.DHTServer object.

            keys: keyManager.Keymanager object.

            certs: certManager.CertManager object.

            verifier: verifier.Verifier object.

            keystore: pisces KeyStore object.

            reactor: twisted reactor.
        """

        endpoint = TCP4ServerEndpoint(reactor, port)
        endpoint.listen(ControlFactory(dht, keys, certs, verifier, keystore, reactor))
