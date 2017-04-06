#!/usr/bin/env python
# -*- coding: utf-8 -*-

from helpers import createKeystore, makeTrustCert, InMemKeyStore, FakeDHT
from p2ppki.backend.certManager import verifyCertSig, VerifyError, CertManager
from pisces.spkilib import spki
import pytest


@pytest.fixture()
def ks():
    return createKeystore()


def test_verifyCertSig(ks):
    keystore = ks[0]
    keys = ks[1]

    seqA = makeTrustCert(keys[0][1], keys[1][0])
    seqB = makeTrustCert(keys[2][1], keys[3][0])

    for elt in seqA:
        if isinstance(elt, spki.PublicKey):
            keyA = elt
        if isinstance(elt, spki.Cert):
            certA = elt
        if isinstance(elt, spki.Signature):
            sigA = elt

    for elt in seqB:
        if isinstance(elt, spki.PublicKey):
            keyB = elt
        if isinstance(elt, spki.Cert):
            certB = elt
        if isinstance(elt, spki.Signature):
            sigB = elt

    res = verifyCertSig(seqA, keystore)
    assert isinstance(res, spki.Sequence)

    c = spki.Sequence(keyA, certA, sigA, keyB)
    with pytest.raises(VerifyError) as e:
        verifyCertSig(c, keystore)
    assert 'More than 1 key found' in str(e.value)

    c = spki.Sequence(keyA, certA, sigA, certB)
    with pytest.raises(VerifyError) as e:
        verifyCertSig(c, keystore)
    assert 'multiple certificates found' in str(e.value)

    c = spki.Sequence(keyA, certA, sigA, sigB)
    with pytest.raises(VerifyError) as e:
        verifyCertSig(c, keystore)
    assert 'multiple signatures found' in str(e.value)

    c = spki.Sequence(keyA, certB, sigB)
    with pytest.raises(VerifyError) as e:
        verifyCertSig(c, keystore)
    assert 'Key and signature principal do not match' in str(e.value)

    c = spki.Sequence(certA, sigB)
    with pytest.raises(VerifyError) as e:
        verifyCertSig(c, keystore)
    assert 'could not verify signature for cert' in str(e.value)

    c = spki.Sequence(certA, sigA)
    with pytest.raises(VerifyError) as e:
        verifyCertSig(c, InMemKeyStore())
    assert 'could not find key to verify signature' in str(e.value)


def test_trust(ks):
    keystore = ks[0]
    keys = ks[1]
    default = keys[0]
    key1 = keys[1]
    key2 = keys[2]
    dht = FakeDHT()

    c = CertManager(dht, keystore)
    c.trust(key2[0].getPrincipal(), key1[0].getPrincipal())
    assert(len(keystore.lookupCertBySubject(key2[0].getPrincipal())) == 1)
    assert(len(keystore.lookupCertByIssuer(key1[0].getPrincipal())) == 1)

    seq = keystore.lookupCertByIssuer(key1[0].getPrincipal())[0]
    assert isinstance(seq[0], spki.Cert)
    assert isinstance(verifyCertSig(seq, keystore), spki.Sequence)
    assert seq[0].getTag().contains('Trusted')
    
    c.trust(key2[0].getPrincipal())
    assert(len(keystore.lookupCertByIssuer(default[0].getPrincipal())) == 1)


