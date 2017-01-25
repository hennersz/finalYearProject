"""A PKCS#1 implementation for the Crypto.PublicKey.RSA module

The Crypto package implements the basic RSA algorithm, but does not
follow PKCS#1, which describes issues like padding, formatting, and
ASN.1 encoding.  The standard is available from:
http://www.rsasecurity.com/rsalabs/pkcs/pkcs-1/

getSignatureImpl(oid)
Returns a subclass of DigestWithRSA that provides the hash function
specified by the oid.

Classes defined here:
DigestInfo -- the ASN.1 encoding of a digest.
RSA_pkcs1 -- wraps an Crypto.PublicKey.RSA key with PKCS#1 encoding
DigestWithRSA -- wraps an RSA_pkcs1 key with sign and verify methods;
    subclasses implement provide implementations of specific hash
    algorithms

"""

import string
from types import TupleType

from Crypto.PublicKey import RSA
from Crypto.Hash import MD2, MD5
from Crypto.Util.number import bytes_to_long, long_to_bytes

from pisces import asn1, algid, cryptrand

class DigestInfo(asn1.ASN1Object):
    def __init__(self, *args):
	self.val = list(args)
        self.digestAlgorithm = None
        self.digest = None
        if args:
            if len(args) == 1:
                apply(self.decode, args)
            else:
                self.digestAlgorithm, self.digest = args

    def decode(self, obj):
        self.digestAlgorithm = algid.AlgorithmIdentifier(obj[0])
        self.digest = obj[1]

    def _encode(self, io):
	contents = [self.digestAlgorithm.encode(),
		    asn1.unparseOctetString(self.digest)]
        io.write(asn1.unparseSequence(contents))
    
    def __cmp__(self, other):
    	return cmp([self.digestAlgorithm.oid, self.digestAlgorithm.params], other[0].val)

def countBits(l):
    """Count the number of bits in the (long) integer l"""
    bits = 0
    while l:
        l = l >> 1
        bits = bits + 1
    return bits

class RSA_pkcs1:
    # constants:
    __PRIVATE = 1
    __PUBLIC = 2

    def __init__(self, key):
	"""Arg is either tuple of strings or an RSA object"""
	# XXX how to signal that we only have half the key pair?
	if type(key) == TupleType:
	    self.key = RSA.construct(key)
	else:
	    self.key = key
        self.keylen = countBits(self.key.n) / 8
        self.max_datalen = self.keylen - 11

    def getPublicComponents(self):
	return self.key.e, self.key.n

    def getPrivateComponents(self):
	return self.key.d, self.key.p, self.key.q

    def encryptPublic(self, plain):
        if len(plain) > self.max_datalen:
            raise ValueError, \
                  "plaintext too long, max length=%d" % self.max_datalen
        block = self.__makeEncryptionBlock(self.__PUBLIC, plain)
        num = bytes_to_long(block)
        cipherNum = self.key._encrypt(num, None)[0] # None parameter is ignored (hopefully)
        return long_to_bytes(cipherNum)

    def decryptPublic(self, cipher):
        num = bytes_to_long(cipher)
        if num >= self.key.n:
            raise ValueError, "cipher text too long"
        plainNum = self.key._encrypt(num, None)[0] # None parameter is ignored (hopefully)
        block = long_to_bytes(plainNum)
        return self.__parseEncryptionBlock(self.__PRIVATE, block)

    def encryptPrivate(self, plain):
        if len(plain) > self.max_datalen:
            raise ValueError, \
                  "plaintext too long, max length=%d" % self.max_datalen
        block = self.__makeEncryptionBlock(self.__PRIVATE, plain)
        num = bytes_to_long(block)
        cipherNum = self.key._decrypt((num,))
        return long_to_bytes(cipherNum)

    def decryptPrivate(self, cipher):
        num = bytes_to_long(cipher)
        if num >= self.key.n:
            raise ValueError, "cipher text too long"
        plainNum = self.key._decrypt((num,))
        block = long_to_bytes(plainNum)
        return self.__parseEncryptionBlock(self.__PUBLIC, block)

    def __parseEncryptionBlock(self, blocktype, block):
        # leading \000 stripped by bytes_to_long/long_to_bytes conversion
        if block[0] != chr(blocktype):
            raise ValueError, "bad blocktype %s" % ord(block[0])
        block = block[1:]
        i = string.find(block, '\000')
        ps = block[:i]
        if len(ps) < 8:
            raise ValueError, "padding string is too small"
        if blocktype == self.__PRIVATE:
            if filter(lambda x:x!='\377', ps):
                raise ValueError, "invalid padding string"
        return block[i+1:]

    def __makeEncryptionBlock(self, blocktype, data):
        padsize = self.keylen - 3 - len(data)
        if blocktype == self.__PRIVATE:
            ps = chr(0xFF) * padsize
        elif blocktype == self.__PUBLIC:
            ps = cryptrand.random(padsize)
            while '\000' in ps:
                clean = string.join(string.split(ps, '\000'), '')
                clean = clean + cryptrand.random(padsize - len(clean))
        else:
            # PKCS #1 defines a second blocktype for private (0), but
            # discourages its use  
            raise ValueError, "unsupported block type %d" % blocktype
        return chr(0) + chr(blocktype) + ps + chr(0) + data

class DigestWithRSA:
    """Base class to combine message digest algorithm with RSA signature"""

    def __init__(self, key):
        if isinstance(key, RSA_pkcs1):
           self.key = key
        elif isinstance(key, RSA.RSAobj):
            self.key = RSA_pkcs1(key)
        else:
            raise ValueError, "invalid key: %s instance of %s" % (key,
                                              key.__class__.__name__)

    def sign(self, data):
        md = self.digest(data)
        enc = DigestInfo(self._digAlgId, md).encode()
        return self.key.encryptPrivate(enc)

    def verify(self, data, sig):
        enc = self.key.decryptPublic(sig)
	try:
	    parsed = asn1.parse(enc)
	except ValueError:
	    return 0
        dig = DigestInfo(parsed)
        if dig.digestAlgorithm != self._digAlgId:
            raise ValueError, \
                  "unexpected digest algorithm: %s" % str(dig.digestAlgorithm)
        md = self.digest(data)
        if md == dig.digest:
            return 1
        return 0

class MD5withRSA(DigestWithRSA):
    _digAlgId = algid.AlgorithmIdentifier([algid.oid_md5, None])
    oid = algid.oid_rsa_md5

    def digest(self, data):
        return MD5.new(data).digest()

class MD2withRSA(DigestWithRSA):
    _digAlgId = algid.AlgorithmIdentifier([algid.oid_md2, None])
    oid = algid.oid_rsa_md2

    def digest(self, data):
        return MD2.new(data).digest()

class signatureLookup:
    __dict = { MD2withRSA.oid : MD2withRSA,
               MD5withRSA.oid : MD5withRSA,
               }
    def __call__(self, algorithmId):
        return self.__dict[algorithmId.oid]

getSignatureImpl = signatureLookup()

def test():
    print "\t-------------"
    print "\tTesting PKCS1"    
    print "\t-------------"
    _key = RSA.generate(1024, cryptrand.random)
    key = RSA_pkcs1(_key)
    
    plain = 'i am un chien andalusia'
    print "\tTesting (encrypt-public/decrypt)... " + plain
    cipher = key.encryptPublic(plain)
    decip = key.decryptPrivate(cipher)
    assert plain == decip, \
           "pisces.pkcs1: Encrypt public/decrypt private failed"

    plain = 'this monkey\'s gone to heaven'
    print "\tTesting (encrypt-private/decrypt)... " + plain
    cipher = key.encryptPrivate(plain)
    decip = key.decryptPublic(cipher)
    assert plain == decip, \
           "pisces.pkcs1: Encrypt private/decrypt public failed"

    # test asn.1 support for DigestInfo
    global x, buf, y
    print "\tTesting ASN.1 Support for DigestInfo encode/decode"
    x = DigestInfo(algid.AlgorithmIdentifier([algid.oid_md5, None]),
		   'x' * 16)
    buf = x.encode()
    y = asn1.parse(buf)
    assert x == y, "pisces.pkcs1: DigestInfo encode/decode failed"
    
    print "\tTesting PKCS1 Signature Verification"
    signer = MD5withRSA(key)
    verifier = MD5withRSA(key)
    sig = signer.sign('foo')
    assert verifier.verify('foo', sig) == 1, \
	   "pisces.pkcs1: Signature verification failed"
    print "\n\n\t------------------"
    print "\tEND OF PKCS1 TESTS"    
    print "\t------------------"

if __name__ == "__main__":
    test()
    
