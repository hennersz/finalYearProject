#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
.. module:: cmdline
    :platform: UNIX
    :synopsis: Connects to local server and sends a command then prints the response.

.. moduleauthor:: Henry Mortimer <henry@morti.net>

"""

from twisted.internet.protocol import Protocol, ClientFactory
from twisted.internet import reactor
from ..config import Config


class CMDLine(Protocol):
    """Protocol for sending a message
    to a socket.
    """

    def sendMessage(self, msg):
        """Appends CRLF to message."""
        self.transport.write(msg + '\r\n')

    def dataReceived(self, data):
        """Sends message if it has just
        connected otherwise print data.
        """

        if data == 'Connected\r\n':
            self.sendMessage(self.factory.msg)
        else:
            print data
            self.transport.loseConnection()


class CMDLineFactory(ClientFactory):
    """Factory class for CMDLine protocol"""

    def __init__(self, msg):
        """Init class"""
        self.msg = msg

    def buildProtocol(self, addr):
        """Contruct Protocol"""
        p = CMDLine()
        p.factory = self
        return p

    def clientConnectionLost(self, connector, reason):
        """Stop reactor on client disconnect"""
        reactor.stop()

    def clientConnectionFailed(self, connector, reason):
        """Stop reactor on client disconnect"""
        print 'Connection failed. Reason:', reason.value
        reactor.stop()


def run(message):
    """Run the program."""
    conf = Config()
    reactor.connectTCP('localhost', conf['localPort'], CMDLineFactory(message))
    reactor.run()
