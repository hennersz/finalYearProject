#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ConfigParser
from distutils.util import strtobool
from os import path


def fullPath(path):
    return path.expanduser(path.expandvars(path))


class Config(dict):

    def __init__(self, loc='~/.p2ppki/config.cfg'):
        self.loc = path.expanduser(loc)
        self.parser = ConfigParser.ConfigParser()
        self.parseConfig()

    def parseConfig(self):
        if self.parser.read(self.loc) == []:
            self.genConfig()
            return

        try:
            self['dataDir'] = fullPath(self.parser.get('settings', 'datadir'))
            self['searchDepth'] = self.parser.getint('settings', 'searchdepth')
            self['verbose'] = self.parser.getboolean('settings', 'verbose')
            self['localPort'] = self.parser.getint('settings', 'localPort')
            self['serverPort'] = self.parser.getint('settings', 'serverPort')
            self['bootStrapServer'] = self.parser.get('setting', 'bootStrapServer')
        except:
            print 'Invalid config file, please see example'

    def genConfig(self):
        print 'No config file found, please create one'
        configLoc = raw_input('Enter file location [%s]: ' % self.loc)
        if configLoc == '':
            configLoc = self.loc
        else:
            self.loc = path.expanduser(configLoc)

        dataDir = raw_input('Enter location for key database [~/.p2ppki]: ')
        if dataDir == '':
            dataDir = '~/.p2ppki'

        searchDepth = raw_input('Enter key search depth [10]: ')
        if searchDepth == '':
            searchDepth = 10
        else:
            searchDepth = int(searchDepth)

        verbose = raw_input('Verbose logging? [True]: ')
        if verbose == '':
            verbose = True
        else:
            verbose = strtobool(verbose)

        localPort = raw_input('Enter port for command listened[8007]: ')
        if localPort == '':
            localPort = 8007
        else:
            localPort = int(localPort)

        serverPort = raw_input('Enter port for DHT connections[8469]: ')
        if serverPort == '':
            serverPort = 8469
        else:
            serverPort = int(serverPort)

        bootStrapServer = raw_input('Enter address of node to bootstrap on[localhost]: ')
        if bootStrapServer == '':
            bootStrapServer = 'localhost'

        self.parser.add_section('settings')
        self.parser.set('settings', 'dataDir', dataDir)
        self.parser.set('settings', 'searchDepth', searchDepth)
        self.parser.set('settings', 'verbose', verbose)
        self.parser.set('settings', 'localPort', localPort)
        self.parser.set('settings', 'serverPort', serverPort)
        self.parser.set('settings', 'bootStrapServer', bootStrapServer)

        self['dataDir'] = fullPath(dataDir)
        self['searchDepth'] = searchDepth
        self['verbose'] = verbose
        self['localPort'] = localPort
        self['serverPort'] = serverPort
        self['bootStrapServer'] = bootStrapServer

        with open(self.loc, 'w+') as confFile:
            self.parser.write(confFile)
