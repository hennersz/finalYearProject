#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
.. module:: verifier
    :platform: UNIX
    :synopsis: Attempts to find valid names for a public key from the dht.

.. moduleauthor:: Henry Mortimer <henry@morti.net>

"""

from pisces.spkilib import verify, database, spki
from twisted.internet.defer import inlineCallbacks, returnValue


def filterNameCerts(certs):
    """Filters a list of spki.Sequence
    objects to remove any non namecert
    objects.

    Args:
        certs: [spki.Sequence]

    Returns:
        [spki.Sequence]
    """

    nameCerts = []
    for seq in certs:
        for elt in seq:
            if isinstance(elt, spki.Cert) and elt.isNameCert():
                nameCerts.append(seq)
    return nameCerts


def filterCerts(certs):
    """Filters a list of spki.Sequence
    objects to only contain sequences with
    spki.Cert objects that aren't namecerts.


    Args:
        certs: [spki.Sequence]

    Returns:
        [spki.Sequence]
    """

    filtered = []
    for seq in certs:
        for elt in seq:
            if isinstance(elt, spki.Cert) and not elt.isNameCert():
                t = elt.getTag()
                if t.contains('CATrusted'):
                    filtered.append(seq)
    return filtered


def getCertFromSeq(seq):
    """Gets the certificate
    object from a spki.Sequence

    Args:
        seq: spki.Sequence

    Returns:
        spki.Cert

    Raises:
        ValueError. Raised if no cert is found.
    """
    for elt in seq:
        if isinstance(elt, spki.Cert):
            return elt
    raise ValueError('Sequence didnt contain certificate')


class Verifier:
    """Attepmts to find valid names for a public key.
    """

    def __init__(self, certManager, keyStore, acl, depth):
        """Init object

        Args:
            certManager: CertManager object.

            keyStore: KeyStore object.

            acl: String or database.ACL object. If its 
            a string it creates a new ACL object.

            dept: Int. The max search depth.
        """

        self.certManager = certManager
        self.keyStore = keyStore
        if isinstance(acl, str):
            self.acl = database.ACL(acl, create=1)
        else:
            self.acl = acl
        self.verifier = verify.ReferenceMonitor(self.acl, self.keyStore, True)
        self.maxDepth = depth

    @inlineCallbacks
    def findChain(self, issuer, depth):
        """Recursively tries to find a valid certificate
        chain by getting certificates for the issuer

        Args:
            issuer: spki.Hash object.

            dept: Int. The current recursion depth.


        Returns:
            Bool. True if chain found otherwise false.
        """

        if depth > self.maxDepth:
            returnValue(False)
        try:
            self.verifier.checkPermission(issuer, 'CATrusted')
        except verify.SecurityError:
            pass
        else:
            returnValue(True)

        certs = yield self.certManager.getCertificates(issuer)
        if certs is None:
            returnValue(False)

        certs = filterCerts(certs)
        if certs is None:
            returnValue(False)

        res = False

        for seq in certs:
            self.keyStore.addCert(seq)
            try:
                self.verifier.checkPermission(issuer, 'CATrusted')
            except verify.SecurityError:
                i = getCertFromSeq(seq).getIssuer().getPrincipal()
                r = yield self.findChain(i, depth+1)
                res = res or r
            else:
                returnValue(True)
        returnValue(res)

    def checkLocalNames(self, keyHash):
        """Checks if there are any name certs
        stored locally for the key.

        Args:
            keyHash: spki.Hash object

        Returns:
            [Strings]: List of names.
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
        return validNames

    @inlineCallbacks
    def checkTrusted(self, keyHash):
        """Checks if any of the keys that 
        issued name certificates for keyHash
        are trusted.

        Args:
            keyHash: spki.Hash object.

        Returns:
            [String]: List of names.
        """

        newCerts = yield self.certManager.getCertificates(keyHash)
        nameCerts = filterNameCerts(newCerts)
        untrustedIssuers = []
        validNames = []

        for seq in nameCerts:
            c = getCertFromSeq(seq)

            #  Slightly unintuitive but name certs should have a
            #  FullyQualifiedName object as the issuer principal
            #  where the principle is the hash of the issuer
            #  and names is a list of names asigned to the key
            i = c.getIssuer().getPrincipal().principal
            if not isinstance(i, spki.Hash):
                continue
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

        returnValue((validNames, untrustedIssuers))

    @inlineCallbacks
    def checkCA(self, untrustedIssuers):
        """Checks each of the untrusted issuers
        to see if there is a valid certificate chain

        Args:
            untrustedIssuers: [(spki,Hash, spki.Sequence)]

        Returns:
            [String]: List of valid names.
        """

        validNames = []
        for issuer in untrustedIssuers:
            found = yield self.findChain(issuer[0], 1)
            if found:
                c = getCertFromSeq(issuer[1])
                self.keyStore.addCert(issuer[1])
                name = c.getIssuer().getPrincipal()
                for n in name.names:
                    validNames.append(n)

        returnValue(validNames)

    @inlineCallbacks
    def identify(self, keyHash):
        """Attepmts to indentify the key

        Args:
            keyHash: spki.Hash.

        Returns:
            [String]: List of names.
        """
        validNames = self.checkLocalNames(keyHash)

        if validNames == []:
            validNames, untrustedIssuers = yield self.checkTrusted(keyHash)

        if validNames == []:
            validNames = yield self.checkCA(untrustedIssuers)

        self.keyStore.save()

        returnValue(validNames)
