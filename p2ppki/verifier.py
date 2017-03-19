#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pisces.spkilib import verify, database, spki
from twisted.internet.defer import inlineCallbacks, returnValue


def filterNameCerts(certs):
    nameCerts = []
    for seq in certs:
        for elt in seq:
            if isinstance(elt, spki.Cert) and elt.isNameCert():
                nameCerts.append(seq)
    return nameCerts


def getCertFromSeq(seq):
    for elt in seq:
        if isinstance(elt, spki.Cert):
            return elt
    raise ValueError('Sequence didnt contain certificate')


class Verifier:

    def __init__(self, certManager, keyStore, aclPath):
        self.certManager = certManager
        self.keyStore = keyStore
        self.acl = database.ACL(aclPath)
        self.verifier = verify.ReferenceMonitor(self.acl, self.keyStore, True)

    @inlineCallbacks
    def identifiy(self, keyHash):
        """keyHash must be a spki.Hash object
        """
        certs = self.keyStore.lookupCertBySubject(keyHash)
        validNames = []
        for cert in certs:
            if isinstance(cert, spki.Sequence):
                for elt in cert:
                    if isinstance(elt, spki.Cert):
                        cert = elt
                        break
            if cert.isNameCert():
                # Assume signatures for local certs have already been validated
                name = cert.getIssuer().getPrincipal()
                for n in name.names:
                    validNames.append(n)

        newCerts = yield self.certManager.getCertificates(keyHash)
        nameCerts = filterNameCerts(newCerts)

        for seq in nameCerts:
            c = getCertFromSeq(seq)

            #  Slightly unintuitive but name certs should have a
            #  FullyQualifiedName object as the issuer principal
            #  where the principle is the hash of the issuer
            #  and names is a list of names asigned to the key
            i = c.getIssuer().getPrincipal().getPrincipal()
            try:
                self.verifier.checkPermission(i, 'Trusted')
            except verify.SecurityError:
                continue
            else:
                self.keyStore.addCert(seq)
                name = cert.getIssuer().getPrincipal()
                for n in name.names:
                    validNames.append(n)

        self.keyStore.save()

        returnValue(validNames)
