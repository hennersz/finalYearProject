#!/usr/bin/env python
# -*- coding: utf-8 -*-

from p2ppki.backend.config import fullPath, Config
import mock


@mock.patch('p2ppki.backend.config.path.expandvars')
@mock.patch('p2ppki.backend.config.path.expanduser')
def test_fullPath(mock_user, mock_vars):
    mock_vars.return_value = '/another/path'
    fullPath('/path/to/somewhere')
    mock_vars.assert_called_with('/path/to/somewhere')
    mock_user.assert_called_with('/another/path')
