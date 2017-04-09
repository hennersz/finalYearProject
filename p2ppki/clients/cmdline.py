#!/usr/bin/env python
# -*- coding: utf-8 -*-

from twisted.internet.protocol import Protocol, ClientFactory
from twisted.internet import reactor
from ..config import Config


class CMDLine(Protocol):
    def sendMessage(self, msg):
        self.transport.write(msg + '\n')

    def dataReceived(self, data):
        if data != 'Connected':
            print data
            self.transport.loseConnection()


class CMDLineFactory(ClientFactory):
    def __init__(self, msg):
        self.msg = msg

    def buildProtocol(self):
        p = CMDLine()
        p.sendMessage(self.msg)
        return p

    def clientConnectionLost(self, connector, reason):
        reactor.stop()

    def clientConnectionFailed(self, connector, reason):
        print 'Connection failed. Reason:', reason.value
        reactor.stop()


def run(message):
    conf = Config()
    reactor.connectTCP('localhost', conf['localPort'], CMDLineFactory(message))
    reactor.run()
