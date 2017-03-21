#!/usr/bin/env python
# -*- coding: utf-8 -*-

from context import p2ppki
from p2ppki.certManager import getDefaultKey, getPassword, resolveName,\
                                parseHashOrName, getHash
from pisces.spkilib import keystore, spki
from pisces.spkilib.spki import PublicKey
from pisces.spkilib.sexp import str_to_b64
import pytest
import mock


pub, priv = spki.makeRSAKeyPair(1024)
priv.
hashString = '(hash md5 |C/qB18lYxADHAPKUdKjRtA==|)'


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

    mock_keystore.getDefaultKey.return_value = None

    with pytest.raises(ValueError):
        getDefaultKey(mock_keystore)


def test_resolveName():
    mock_keystore = mock.create_autospec(keystore.KeyStore)

    mock_keystore.lookupName.return_value = None

    with pytest.raises(ValueError):
        resolveName('name', mock_keystore)

    n = spki.makeNameCert(pub.getPrincipal(), pub.getPrincipal(), 'name')
    sig = priv.sign(n)
    nameCert = spki.Sequence(n, sig)

    mock_keystore.lookupName.return_value = [nameCert]

    assert resolveName('name', mock_keystore).getPrincipal() == pub.getPrincipal()


@mock.patch('p2ppki.certManager.getDefaultKey')
def test_parseHashOrName(mock_getDefaultKey):
    mock_keystore = mock.create_autospec(keystore.KeyStore)

    res = parseHashOrName(hashString, mock_keystore)
    assert spki.isa(res, spki.Hash)
    assert str_to_b64(res.value) == 'C/qB18lYxADHAPKUdKjRtA=='

    mock_getDefaultKey.return_value = pub.getPrincipal()
    
    res = parseHashOrName('name', mock_keystore)
    assert res.principal == pub.getPrincipal()
    assert len(res.names) == 1
    assert res.names[0] == 'name'


@mock.patch('p2ppki.certManager.getDefaultKey')
@mock.patch('p2ppki.certManager.resolveName')
def test_getHash(mock_resolveName, mock_getDefaultKey):
    mock_keystore = mock.create_autospec(keystore.KeyStore)

    mock_resolveName.return_value = pub
    mock_getDefaultKey.return_value = pub.getPrincipal()

    res = getHash('name', mock_keystore)
    assert res == pub.getPrincipal()

    res = getHash(hashString, mock_keystore)
    assert spki.isa(res, spki.Hash)
    assert str_to_b64(res.value) == 'C/qB18lYxADHAPKUdKjRtA=='


def test_loadPrivateKey():
    pass


def test_getCertSubjectHash():
    pass


def test_verifyCertSig():
    pass
