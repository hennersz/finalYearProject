#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
.. module:: cmd_runner
    :platform: UNIX
    :synopsis: Reads a list of commands from a file, connects to the local server and runs them

.. moduleauthor:: Henry Mortimer <henry@morti.net>

"""

from twisted.internet.protocol import Protocol, ClientFactory
from twisted.internet import reactor
from ..config import Config


class CMDRunner(Protocol):
    """Sends commands from a file until
    it is empty. It waits for a response
    before sending each command.
    """

    def sendMessage(self, msg):
        """Appends CRLF to message"""

        self.transport.write(msg + '\r\n')

    def dataReceived(self, data):
        """Checks if there is another
        message to send and sends it
        or disconnects.
        """

        try:
            msg = self.factory.lines.next()[:-1]
        except StopIteration:
            self.transport.loseConnection()
        else:
            self.sendMessage(msg)


class CMDRunnerFactory(ClientFactory):
    """Creates client factory for CMDRunner"""

    def __init__(self, lines):
        """Turn lines into iterator

        Args:
            Lines; List.
        """

        self.lines = iter(lines)

    def startedConnecting(self, connector):
        """Send message on startup"""
        print 'Connecting...'

    def buildProtocol(self, addr):
        """Create protocol and give it a
        reference to the factory.
        """
        print 'Connected'
        p = CMDRunner()
        p.factory = self
        return p

    def clientConnectionLost(self, connector, reason):
        """Stop reactor on client disconnect"""
        print 'Lost connection.  Reason:', reason.value
        reactor.stop()

    def clientConnectionFailed(self, connector, reason):
        """Stop reactor on client disconnect"""
        print 'Connection failed. Reason:', reason.value
        reactor.stop()


def run(fp):
    """Run this program

    Args:
        fp: File object in read mode.
    """

    conf = Config()
    lines = fp.readlines()
    reactor.connectTCP('localhost', conf['localPort'], CMDRunnerFactory(lines))
    reactor.run()
