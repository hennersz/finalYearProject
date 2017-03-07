from pisces.spkilib import spki, sexp


def getDefaultKey(keyStore, returnHash=True):
    """Gets the default key from a keystore
    """
    privKeyHash = keyStore.getDefaultKey()
    key = keyStore.lookupKey(privKeyHash)
    print key.__class__.__name__
    if returnHash:
        return key.getPrincipal()
    else:
        return key


def resolveName(name, keyStore):
    """Convert a name in the local namespace to a key

    The return value is an object with a getPrincipal method.

    Based on the pisces function but without global variables
    """
    nameCerts = keyStore.lookupName(name)

    if not nameCerts:
        raise ValueError("unbound SPKI name: %s" % name)
    cert = spki.extractSignedCert(nameCerts[0])

    return cert.getSubject()


def parseHashOrName(buf, keyStore):
    """Try parsing into a hash or a name
    """

    try:
        o = spki.parseText(buf)
    except sexp.ParseError:
        pass
    else:
        return o

    # It wasnt a hash, try as name
    base = getDefaultKey(keyStore)
    return spki.FullyQualifiedName(base, (buf,))


def getIssuer(issuer, keyStore):
    # could be a hash or a name
    obj = parseHashOrName(issuer, keyStore)
    if isinstance(obj, spki.Name):
        return resolveName(obj, keyStore).getPrincipal()
    else:
        return obj


class CertManager():
    def __init__(self, dht, keyStore):
        self.dht = dht
        self.keystore = keyStore

    def trust(self, subject, issuer=None):
        if issuer is None:
            issuer = getDefaultKey(self.keystore)

        i = getIssuer(issuer, self.keystore)
        s = parseHashOrName(subject, self.keystore)

        enc_privkey = self.keystore.lookupPrivateKey(i)
        privkey = enc_privkey.decrypt()

        perm = spki.eval(sexp.parseText('(* set Trusted)'))

        c = spki.makeCert(i, s, spki.Tag(perm))
        seq = spki.Sequence()
        seq.extend([c, privkey.sign(c)])
        self.keystore.addCert(seq)
        self.keystore.save()
