"""Handle for X.509 AlgorithmIdentifier objects

This module understands a minimal number of OIDS, just enough X.509
stuff needed for PKCS 1 & 7.
"""

import types

from pisces import asn1

oid_dsa = asn1.OID((1, 2, 840, 10040, 4, 1))
oid_dsa_sha1 = asn1.OID((1, 2, 840, 10040, 4, 3))
oid_rsa = asn1.OID((1, 2, 840, 113549, 1, 1, 1))
oid_rsa_md2 = asn1.OID((1, 2, 840, 113549, 1, 1, 2))
oid_rsa_md5 = asn1.OID((1, 2, 840, 113549, 1, 1, 4))
oid_md2 = asn1.OID((1, 2, 840, 113549, 2, 2))
oid_md5 = asn1.OID((1, 2, 840, 113549, 2, 5))
oid_sha = asn1.OID((1, 3, 14, 3, 2, 26))

class AlgorithmIdentifier(asn1.ASN1Object):
    """the type of the algorithm plus optional parameters

    public read-only attributes: oid, params, name

    AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }

    defined by X.509
    """

    __dict = {oid_dsa_sha1: 'dsaWithSha1',
              oid_rsa_md2: 'md2withRSAEncryption',
              oid_rsa_md5: 'md5withRSAEncryption',
              oid_rsa: 'rsa',
              oid_dsa: 'dsa',
              oid_sha: 'sha',
              oid_md2: 'md2',
              oid_md5: 'md5',
              }
    
    def __init__(self, obj=None, params=None):
        self.oid = None
        self.params = None
        self.name = None
        if obj and (isinstance(obj, asn1.Sequence)
                    or type(obj) == types.ListType):
            self._decode(obj)
        elif obj:
            assert isinstance(obj, asn1.OID)
            self.oid = obj
            self.params = params
        self.name = self.__dict.get(self.oid, None)

    def _decode(self, obj):
        self.oid, self.params = obj

    def __cmp__(self, other):
		if isinstance(other, AlgorithmIdentifier):
			return cmp((self.oid, self.params), (other.oid, other.params)) 
		elif isinstance(other, asn1.Sequence):
			return cmp([self.oid, self.params], other.val)
		elif isinstance(other, list):
			# Because python passes by assignment, the val is taken on comparison. Therefore we check for list (as returned by calling .val).
			return cmp([self.oid, self.params], other)
		return -1
        
    def __repr__(self):
        if self.params:
            return "<%s: %s>" % (self.name or self.oid, self.params)
        else:
            return "<" + (self.name or repr(self.oid)) + ">"

    def _encode(self, io):
        contents = [self.oid.encode()]
        if self.params:
        	contents.append(self.params.encode())
        else:
        	contents.append(asn1.unparseNull())
        	io.write(asn1.unparseSequence(contents))

def test():
    global x, buf, y
    x = AlgorithmIdentifier(oid_rsa_md5, None)
    buf = x.encode()
    y = asn1.parse(buf)
    assert x == y, "pisces.algid: AlgorithmIdentifier encode/decode failed"

if __name__ == "__main__":
    test()
