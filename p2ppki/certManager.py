from pisces.spkilib import spki, sexp
from pisces.spkilib.config import parseHashOrName, resolveName


def getIssuer(issuer):
    # could be a hash or a name
    obj = parseHashOrName(issuer)
    if isinstance(obj, spki.Name):
        return resolveName(obj).getPrincipal()
    else:
        return obj


class CertManager():
    def __init__(self, dht, keyStore):
        self.dht = dht
        self.keystore = keyStore

    def trust(self, issuer, subject):
        i = getIssuer(issuer)
        s = parseHashOrName(subject)
        enc_privkey = self.keystore.lookupPrivateKey(i)
        privkey = enc_privkey.decrypt()
        perm = spki.eval(sexp.parseText('(Trusted)'))
        c = spki.makeCert(i, s, spki.Tag(perm))
        seq = spki.Sequence([c, privkey.sign(c)])
        self.keystore.addCert(seq)
