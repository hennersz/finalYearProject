#!/usr/bin/env python
# -*- coding: utf-8 -*-

from helpers import createKeystore, makeTrustCert
from p2ppki.backend.certManager import verifyCertSig, VerifyError
from pisces.spkilib import spki
import copy
import pytest
import mock


@pytest.fixture()
def ks():
    return createKeystore()


def test_verifyCertSig(ks):
    keystore = ks[0]
    keys = ks[1]

    certA = makeTrustCert(keys[0][1], keys[1][0])
    certB = makeTrustCert(keys[2][1], keys[3][0])

    for elt in certB:
        if isinstance(elt, spki.PublicKey):
            key = elt
        if isinstance(elt, spki.Cert):
            cert = elt
        if isinstance(elt, spki.Signature):
            sig = elt

    res = verifyCertSig(certA, keystore)
    assert isinstance(res, spki.Sequence)
    
    c = copy.copy(certA)
    c.append(key)
    with pytest.raises(VerifyError):
        verifyCertSig(c, keystore)
        
    c = copy.copy(certA)
    c.append(cert)
    with pytest.raises(VerifyError):
        verifyCertSig(c, keystore)

    c = copy.copy(certA)
    c.append(sig)
    with pytest.raises(VerifyError):
        verifyCertSig(c, keystore)
