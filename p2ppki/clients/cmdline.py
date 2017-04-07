#!/usr/bin/env python
# -*- coding: utf-8 -*-

from twisted.internet.protocol import Protocol, ClientFactory
from twisted.internet import reactor
import argparse
import sys


def getArgs(args=sys.argv):
    parser = argparse.ArgumentParser(description="reads a command\
            and sends them to a local tcp socket")

    parser.add_argument('-d', '--domain',
                        nargs='?',
                        type=str,
                        default='localhost')
    parser.add_argument('-p', '--port',
                        nargs='?',
                        type=int,
                        default=8007
                        )
    parser.add_argument('message',
                        type=str)

    args = parser.parse_args(args)
    return args


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


def run(args):
    a = getArgs(args)
    reactor.connectTCP(a.domain, a.port, CMDLineFactory(a.message))
    reactor.run()


if __name__ == '__main__':
    run(sys.argv[1:])
