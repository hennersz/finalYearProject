#!/usr/bin/env python
# -*- coding: utf-8 -*-

from context import p2ppki
from p2ppki.certManager import getDefaultKey, getPassword
from pisces.spkilib import keystore
from pisces.spkilib.spki import PublicKey
import mock


@mock.patch('p2ppki.certManager.getpass.getpass')
def test_getPassword(mock_getpass):
    mock_getpass.side_effect = ['password', 'password']
    assert getPassword('prompt') == 'password'
    assert mock_getpass.call_count == 2

    mock_getpass.side_effect = ['password', 'a password', 'password', 'password']
    assert getPassword('prompt') == 'password'
    assert mock_getpass.call_count == 6


def test_getDefaultKey():
    mock_keystore = mock.create_autospec(keystore.KeyStore)
    mock_PubKey = mock.create_autospec(PublicKey)

    mock_keystore.getDefaultKey.return_value = 'key_hash'
    mock_keystore.lookupKey.return_value = mock_PubKey
    mock_PubKey.getPrincipal.return_value = 'hash'

    res = getDefaultKey(mock_keystore)
    mock_keystore.getDefaultKey.assert_called()
    mock_keystore.lookupKey.assert_called_with('key_hash')
    mock_PubKey.getPrincipal.assert_called()
    assert res == 'hash'
    
    res = getDefaultKey(mock_keystore, returnHash=False)
    mock_keystore.getDefaultKey.assert_called()
    mock_keystore.lookupKey.assert_called_with('key_hash')
    assert res == mock_PubKey
