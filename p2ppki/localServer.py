from twisted.internet import reactor
from twisted.internet.protocol.basic import LineReceiver
from twisted.internet.protocol import Factory
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.defer import inlineCallbacks
import getopt

class ControlProtocol(LineReceiver):

    def __init__(self, dht):
        Protocol.__init__(self)
        self.dht = dht
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

    @inlineCallbacks 
    def handleGet(self, args):
        if(len(args) != 1):
            self.sendLine("GET usage: GET <key>")
        else:
            value = yield dht.get(args[0])
            if value is not None:
                self.sendLine("Found data: %s", str(value))
            else:
                self.sendLine("No data for key: %s", args[0])

    def handleSet(self, args):
        if(len(args) != 2):
            self.sendLine("SET usage: SET <key> <value>")
        else:
            self.sendLine("Setting value %s for key %s in DHT", args[1], args[0])
            success = yield self.dht.set(args[0], args[1])
            if seccess:
                self.sendLine("Success!")
            else:
                self.sendLine("Faliure :(")

    def handleUnknown(self, command):
        self.sendLine("Unknown command: %s", command)
        self.sendLine("Supported commands: %s", str(self.supportedCommands))




class ControlFactory(Factory):
    def __init__(self, dht):
        Factory.__init__(self)
        self.dht = dht
    def buildProtocol(self, addr):
        return ControlProtocol(self.dht)

class ControlServer(object):
    def __init__(self, port, dht):
        endpoint = TCP4ServerEndpoint(reactor, port)
        endpoint.listen(ControlFactory(dht))
