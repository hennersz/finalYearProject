#!/usr/bin/env python
# -*- coding: utf-8 -*-

from p2ppki.utils import getPassword, getDefaultKey, hashToB64,\
        parseKeyIdInput, loadPrivateKey, getCertSubjectHash
from helpers import createKeystore, InMemKeyStore, makeNameCert
from pisces.spkilib import spki, sexp
import pytest
import mock


@pytest.fixture()
def ks():
    return createKeystore()


@mock.patch('p2ppki.utils.getpass.getpass')
def test_getPassword(mock_getpass):
    mock_getpass.side_effect = ['password', 'password']
    assert getPassword('prompt') == 'password'
    assert mock_getpass.call_count == 2

    mock_getpass.side_effect = ['password', 'a password', 'password', 'password']
    assert getPassword('prompt') == 'password'
    assert mock_getpass.call_count == 6


def test_getDefaultKey(ks):
    keystore = ks[0]
    defaultKey = ks[1][0]

    res = getDefaultKey(keystore, returnHash=False)
    assert isinstance(res, spki.PublicKey)
    assert res.getPrincipal() == defaultKey[0].getPrincipal()

    res = getDefaultKey(keystore)
    assert isinstance(res, spki.Hash)
    assert res == defaultKey[0].getPrincipal()

    emptyKeystore = InMemKeyStore()

    with pytest.raises(ValueError):
        getDefaultKey(emptyKeystore)


def test_parseKeyIdInput(ks):
    keystore = ks[0]
    defaultKey = ks[1][0]
    otherKey = ks[1][1]

    h = defaultKey[0].getPrincipal()
    h64 = hashToB64(h)
    hsexp = str(h.sexp())

    cert = makeNameCert(defaultKey[1], otherKey[0], 'Alice')
    keystore.addCert(cert)

    cert = makeNameCert(defaultKey[1], ks[1][2][0], 'Charlie')
    keystore.addCert(cert)

    cert = makeNameCert(defaultKey[1], ks[1][3][0], 'Charlie')
    keystore.addCert(cert)

    res = parseKeyIdInput(hsexp, keystore)
    assert isinstance(res, spki.Hash)
    assert res == h

    res = parseKeyIdInput(h64, keystore)
    assert isinstance(res, spki.Hash)
    assert res == h

    res = parseKeyIdInput('Alice', keystore)
    assert isinstance(res, spki.Hash)
    assert res == otherKey[0].getPrincipal()

    with pytest.raises(ValueError):
        parseKeyIdInput('oiwoenvwoivn', keystore, parseName=False)

    with pytest.raises(NameError):
        parseKeyIdInput('Bob', keystore)

    with pytest.raises(NameError):
        parseKeyIdInput('Charlie', keystore)


@mock.patch('p2ppki.utils.getPassword')
def test_loadPrivateKey(mock_getPassword, ks):
    keystore = ks[0]
    emptyKeystore = InMemKeyStore()
    defaultKey = ks[1][0]
    otherKey = ks[1][1]

    mock_getPassword.return_value = 'password'

    pub, priv = spki.makeRSAKeyPair(1024)
    keystore.addPrivateKey(priv, pub, 'password')
    keystore.addPublicKey(pub)

    res = loadPrivateKey(keystore)
    assert res.getPrincipal() == defaultKey[0].getPrincipal()

    res = loadPrivateKey(keystore, otherKey[0].getPrincipal())
    assert res.getPrincipal() == otherKey[1].getPrincipal()

    res = loadPrivateKey(keystore, pub.getPrincipal())
    assert res.getPrincipal() == priv.getPrincipal()

    with pytest.raises(ValueError):
        loadPrivateKey(emptyKeystore)


def test_getCertSubjectHash(ks):
    keystore = ks[0]
    defaultKey = ks[1][0]
    otherKey = ks[1][1]

    cert = makeNameCert(defaultKey[1], otherKey[0], 'Alice')
    keystore.addCert(cert)

    name = spki.FullyQualifiedName(defaultKey[1].getPrincipal, ['Alice'])
    perm = spki.Tag(spki.eval(sexp.parseText('(*)')))
    c = spki.makeCert(ks[1][2][0].getPrincipal(), name, perm)
    sig = ks[1][2][1].sign(c)
    otherCert = spki.Sequence(c, sig)

    res = getCertSubjectHash(cert, keystore)
    assert res == otherKey[0].getPrincipal()

    res = getCertSubjectHash(otherCert, keystore)
    assert res == otherKey[0].getPrincipal()

    with pytest.raises(ValueError):
        getCertSubjectHash(otherCert, InMemKeyStore())


def test_hashToB64(ks):
    h = ks[1][0][0].getPrincipal()
    with pytest.raises(ValueError):
        hashToB64('9wr9h9ruhv')

    res = hashToB64(h)
    assert len(res) == 24
    assert res[-2:] == '=='
