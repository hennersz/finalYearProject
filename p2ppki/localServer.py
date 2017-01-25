from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.internet.endpoints import TCP4ServerEndpoint

class ControlProtocol(Protocol):
    def __init__(self, dht):
        Protocol.__init__(self)
        self.dht = dht

    def dataReceived(self, data):
        print data

class ControlFactory(Factory):
    def __init__(self, dht):
        Factory.__init__(self)
        self.dht = dht
    def buildProtocol(self, addr):
        return ControlProtocol(self.dht)

class ControlServer(object):
    def __init__(self, port, dht):
        endpoint = TCP4ServerEndpoint(reactor, port)
        endpoint.listen(ControlFactory())
        self.dht = dht


