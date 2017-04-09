#!/usr/bin/env python
# -*- coding: utf-8 -*-

from p2ppki.config import fullPath, Config
import mock
import StringIO


@mock.patch('p2ppki.backend.config.path.expandvars')
@mock.patch('p2ppki.backend.config.path.expanduser')
def test_fullPath(mock_user, mock_vars):
    mock_vars.return_value = '/another/path'
    fullPath('/path/to/somewhere')
    mock_vars.assert_called_with('/path/to/somewhere')
    mock_user.assert_called_with('/another/path')


@mock.patch('p2ppki.backend.config.open')
def test_Config(mock_open):
    mock_open.return_value = StringIO.StringIO('[settings]\n\
datadir = /Users/henrymortimer/.p2ppki\n\
searchdepth = 10\n\
verbose = True\n\
localport = 8007\n\
serverport = 8469\n\
bootstrapserver = localhost\n')
    c = Config()
    assert c['dataDir'] == '/Users/henrymortimer/.p2ppki'
    assert c['searchDepth'] == 10
    assert c['verbose']
