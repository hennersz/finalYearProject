from twisted.internet import reactor
from twisted.protocols.basic import LineReceiver
from twisted.internet.protocol import Factory
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.defer import inlineCallbacks

from distutils.util import strtobool


class ControlProtocol(LineReceiver):
    self.supportedCommands = ['GET', 'SET']

    def connectionMade(self):
        self.sendLine("Connected")

    def lineReceived(self, line):
        data = line.split()
        command = data[0].upper()

        args = data[1:]
        if command == 'GET':
            self.handleGet(args)
        elif command == 'SET':
            self.handleSet(args)
        else:
            self.handleUnknown(data[0])

    def handleList(self, args):
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

    @inlineCallbacks
    def handleGet(self, args):
        if(len(args) != 1):
            self.sendLine("GET usage: GET <key>")
        else:
            value = yield self.dht.get(args[0])
            if value is not None:
                self.sendLine("Found data: %s" % (str(value)))
            else:
                self.sendLine("No data for key: %s" % (args[0]))

    @inlineCallbacks
    def handleSet(self, args):
        if(len(args) != 2):
            self.sendLine("SET usage: SET <key> <value>")
        else:
            self.sendLine("Setting value %s for key %s in DHT" %
                          (args[1], args[0]))
            success = yield self.dht.set(args[0], args[1])
            if success:
                self.sendLine("Success!")
            else:
                self.sendLine("Faliure :(")

    def handleUnknown(self, command):
        self.sendLine("Unknown command: %s" % (command))
        self.sendLine("Supported commands: %s" % (str(self.supportedCommands)))


class ControlFactory(Factory):
    protocol = ControlProtocol

    def __init__(self, dht, keys, certs, verifier):
        self.dht = dht
        self.keys = keys
        self.certs = certs
        self.verifier = verifiier


class ControlServer(object):
    def __init__(self, port, dht):
        endpoint = TCP4ServerEndpoint(reactor, port)
        endpoint.listen(ControlFactory(dht))
