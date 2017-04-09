#!/usr/bin/env python
# -*- coding: utf-8 -*-

from p2ppki.backend.server import runServer
from p2ppki.clients import cmd_runner, cmdline
from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from p2ppki.config import Config
import argparse
import daemon


class Stop(Protocol):
    def stop(self):
        self.transport.write('STOP\r\n')
        self.transport.loseConnection()
        reactor.stop()
        print 'stopped'


def connected(p):
    p.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='cmd')

    startServer = subparsers.add_parser('startServer')
    stopServer = subparsers.add_parser('stopServer')
    runFile = subparsers.add_parser('runFile')
    runCommand = subparsers.add_parser('runCommand')

    runFile.add_argument('file', type=argparse.FileType('r'))
    runCommand.add_argument('command', type=str)

    args = parser.parse_args()

    if args.cmd == 'startServer':
        with daemon.DaemonContext():
            runServer()
    elif args.cmd == 'stopServer':
        conf = Config()
        point = TCP4ClientEndpoint(reactor, 'localhost', conf['localPort'])
        d = connectProtocol(point, Stop())
        d.addCallback(connected)
        reactor.run()
    elif args.cmd == 'runFile':
        cmd_runner.run(args.file)
    elif args.cmd == 'runCommand':
        cmdline.run(args.command)
    else:
        parser.print_usage()
