#!/usr/bin/env python
# -*- coding: utf-8 -*-

from twisted.internet.protocol import Protocol, ClientFactory
from twisted.internet import reactor

import argparse
import sys


def getArgs():
    parser = argparse.ArgumentParser(description="reads commands from a file\
            and sends them to a local tcp socket")

    parser.add_argument('file',
                        nargs='?',
                        type=argparse.FileType('r'),
                        default=sys.stdin,
                        help='The input command file')
    parser.add_argument('-d', '--domain',
                        nargs='?',
                        type=str,
                        default='localhost')
    parser.add_argument('-p', '--port',
                        nargs='?',
                        type=int,
                        default=8007
                        )
    args = parser.parse_args()
    return args


class CMDRunner(Protocol):
    def sendMessage(self, msg):
        self.transport.write(msg)

    def dataReceived(self, data):
        try:
            msg = self.factory.lines.next()
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


if __name__ == '__main__':
    args = getArgs()
    lines = args.file.readlines()
    reactor.connectTCP(args.domain, args.port, CMDRunnerFactory(lines))
    reactor.run()
