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
    
    c = copy.copy(seqA)
    c.append(keyB)
    with pytest.raises(VerifyError):
        verifyCertSig(c, keystore)
        
    c = copy.copy(seqA)
    c.append(certB)
    with pytest.raises(VerifyError):
        verifyCertSig(c, keystore)

    c = copy.copy(seqA)
    c.append(sigB)
    with pytest.raises(VerifyError):
        verifyCertSig(c, keystore)
