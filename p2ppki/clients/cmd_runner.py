#!/usr/bin/env python
# -*- coding: utf-8 -*-

from twisted.internet.protocol import Protocol, ClientFactory
from twisted.internet import reactor
from ..config import Config


class CMDRunner(Protocol):
    def sendMessage(self, msg):
        self.transport.write(msg + '\r\n')

    def dataReceived(self, data):
        try:
            msg = self.factory.lines.next()[:-1]
        except StopIteration:
            self.transport.loseConnection()
        else:
            self.sendMessage(msg)


class CMDRunnerFactory(ClientFactory):
    def __init__(self, lines):
        self.lines = iter(lines)

    def startedConnecting(self, connector):
        print 'Connecting...'

    def buildProtocol(self, addr):
        print 'Connected'
        p = CMDRunner()
        p.factory = self
        return p

    def clientConnectionLost(self, connector, reason):
        print 'Lost connection.  Reason:', reason.value
        reactor.stop()

    def clientConnectionFailed(self, connector, reason):
        print 'Connection failed. Reason:', reason.value
        reactor.stop()


def run(fp):
    conf = Config()
    lines = fp.readlines()
    reactor.connectTCP('localhost', conf['localPort'], CMDRunnerFactory(lines))
    reactor.run()
