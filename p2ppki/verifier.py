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


def filterCerts(certs):
    filtered = []
    for seq in certs:
        for elt in seq:
            if isinstance(elt, spki.Cert) and not elt.isNameCert():
                filtered.append(seq)
    return filtered


def getCertFromSeq(seq):
    for elt in seq:
        if isinstance(elt, spki.Cert):
            return elt
    raise ValueError('Sequence didnt contain certificate')


class Verifier:

    def __init__(self, certManager, keyStore, aclDir, depth):
        self.certManager = certManager
        self.keyStore = keyStore
        self.acl = database.ACL(aclDir, create=1)
        self.verifier = verify.ReferenceMonitor(self.acl, self.keyStore, True)
        self.maxDepth = depth

    @inlineCallbacks
    def findChain(self, issuer, depth):
        if depth > self.maxDepth:
            returnValue(False)
        certs = yield self.certManager.getCertificates(issuer)
        certs = filterCerts(certs)
        res = False
        for seq in certs:
            self.keyStore.addCert(seq)
            try:
                self.verifier.checkPermission(issuer, 'CATrusted')
            except verify.SecurityError:
                i = getCertFromSeq(seq).getIssuer().getPrincipal()
                r = yield findChain(i, depth+1)
                res = res or r
        returnValue(res)

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

        if validNames == []:
            newCerts = yield self.certManager.getCertificates(keyHash)
            nameCerts = filterNameCerts(newCerts)
            untrustedIssuers = []

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
                    try:
                        self.verifier.checkPermission(i, 'CATrusted')
                    except:
                        untrustedIssuers.append((i, seq))
                    else:
                        self.keyStore.addCert(seq)
                        name = c.getIssuer().getPrincipal()
                        for n in name.names:
                            validNames.append(n)
                else:
                    self.keyStore.addCert(seq)
                    name = c.getIssuer().getPrincipal()
                    for n in name.names:
                        validNames.append(n)

        if validNames == []:
            for issuer in untrustedIssuers:
                found = yield self.findChain(issuer[0], 1)
                if found:
                    c = getCertFromSeq(issuer[1])
                    self.keyStore.addCert(issuer[1])
                    name = c.getIssuer().getPrincipal()
                    for n in name.names:
                        validNames.append(n)

        self.keyStore.save()

        returnValue(validNames)
