#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ConfigParser
from distutils.util import strtobool
from os import path

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
            self['dataDir'] = self.parser.get('settings', 'datadir')
            self['searchDepth'] = self.parser.getint('settings', 'searchdepth')
            self['verbose'] = self.parser.getboolean('settings', 'verbose')
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
            dataDir = path.expanduser('~/.p2ppki')
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

        self['dataDir'] = dataDir
        self['searchDepth'] = searchDepth
        self['verbose'] = verbose

        self.parser.add_section('settings')
        self.parser.set('settings', 'dataDir', dataDir)
        self.parser.set('settings', 'searchDepth', searchDepth)
        self.parser.set('settings', 'verbose', verbose)

        with open(self.loc, 'w+') as confFile:
            self.parser.write(confFile)
