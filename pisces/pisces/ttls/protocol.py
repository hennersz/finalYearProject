"""Trivial transport layer security

This protocol is loosely based on the TLS protcol (RFC 2446).  There
is no reason to believe that this new protocol offers any of the
security guarantees of the real TLS protocol.  It does use some of the 
same basic ideas, and it might be possible to show that it is secure.

Working notes

If this is a spki-style protocol, we ought to use sexps package the
data instead of the TLS-style structs.

The basic record will be a tuple (type, compression_method,
protection_method, mac, data), where the type is a string naming the
higher level protocol used to process the enclosed data.  Compression
method is a string naming the compression method used.  Meaningful
names are 'null' and 'zlib'.  Protection is the kind of payload
protection, e.g. MAC, stream or block cipher, etc.  The mac slot is
the MAC for the compressed, but un-encrypted data. The payload data
is first compressed and then protected.

Not exactly clear what data is passed into the MAC and cipher
functions yet.  Need to decide about padding, for example.

XXX Need a satisfactory pseudo-random number generator for Solaris and 
a Python interface to same.  It sounds like Yarrow would be nice to
use, except that it is only available for Windows at the moment.

To limit the complexity of the initial implementation, I will use the
following set of algorithms: RSA, 3DES, MD5: RSA_WITH_3DES_EDE_CBC_MD5.
This, unfortunately, is a choice that isn't available in the TLS RFC.
The closest choice would be with SHA instead of MD5, but that's a bit
inconvenient because all the SPKI stuff use RSA_with_MD5.
The DES stuff in PCT doesn't seem very helpful with key generation;
apparently, no test for weak keys and nothing to help with the fact
that they keys are only 56 bits.  I'll start with a helper function
that won't work very well.  Also need to think about padding.

I'm going to avoid most of the negotation for version 0 of the
protocol -- the cipher suite and compression will be constant.
So the basic protocol looks like this--

The order of TLS message is --

   C->S (client-hello session-id random)
   S->C (server-hello session-id random)
   S->C (certificate ...) *
   S->C (server-key-exchange ...) *
   S->C (certificate-request ...) *
   S->C (server-hello-done ...)
   C->S (certificate ...) *
   C->S (client-key-exchange ...)
   C->S (certificate-verify ...) *
   [C->S (change-cipher-spec ...)]
   C->S (finished ...)
   [S->C (change-cipher-spec ...)]
   S->C (finished ...)

The server-key-exchange and client-key-exchange (?) are not needed
here because we are using RSA and not worrying about export issues.
The RSA key is sufficient for exchanging the premaster secret.

"""

from pisces import spkilib
from pisces.spkilib.sexp import parse, object_to_sexp
from pisces import cryptrand, hmac
from Crypto.Hash import MD5, SHA
from Crypto.Cipher import DES3
from Crypto.Util.number import long_to_bytes, bytes_to_long

import string
import time
import types
import zlib
import cStringIO

# collection of misc constants
SESSION_ID_SIZE = 16

class Message(spkilib.spki.SPKIObject):
    pass

class Random(Message):

    def __init__(self, t, rand):
        self.rand = rand
        if type(t) == types.StringType:
            self.t = int(t)
        else:
            self.t = t

    def sexp(self):
        return parse(['random', str(self.t), self.rand])

def newRandom(size):
    t = int(time.time())
    randBuf = cryptrand.random(size)
    return Random(t, randBuf)

class Hello(Message):
    RANDOM_SIZE = 28

class ClientHello(Hello):
    # omits most of the interesting stuff from the TLS client hello
    # because we're not re-using sessions and we don't negotiate
    # security parameters
    
    def __init__(self, ver, rand):
        self.ver = ver
        self.rand = rand
        assert ver == '0', 'invalid TTLS version'

    def sexp(self):
        return parse(['client-hello', self.ver,
                      object_to_sexp(self.rand)]) 

def newClientHello():
    return ClientHello('0', newRandom(ClientHello.RANDOM_SIZE))
    
class ServerHello(Hello):
    # XXX for now sessId is just a string.  defined by TLS as
    # opaque<0..32> 
    def __init__(self, ver, rand, sessId):
        self.ver = ver
        self.rand = rand
        self.sessId = sessId
        assert ver == '0', 'invalid TTLS version'

    def sexp(self):
        return parse(['server-hello', self.ver,
                      object_to_sexp(self.rand), self.sessId])
    
def newServerHello():
    return ServerHello('0', newRandom(ServerHello.RANDOM_SIZE),
                       cryptrand.random(SESSION_ID_SIZE))

class Certificate(Message):
    """Contains a sequence of certificates starting with sender's cert"""
    # XXX contains a sequence of certificates -- but should it just be 
    # a Sequence?  the sender's cert must be first!  if the sender's
    # cert does not contain the public-key, it must be preceded by the 
    # public-key

    # XXX the cert for the server itself ought to contain the key
    # rather than a hash of the key.  not sure how this will play out
    # in the API.

    # XXX does it make sense to send more than the single cert for the 
    # server?
    
    def __init__(self, certs):
        assert isinstance(certs, spkilib.spki.Sequence)
        self.certs = certs
        self.__verify = 0

    def getPrincipal(self):
        # XXX this is dodgy; need to call verify first...
        sender = self.certs[0]
        return sender.subject.getPrincipal()

    def verify(self):
        """Verify the certificate chain received"""
        # XXX not implemented
        self.__verify = 1
        return 'not-implemented-yet'

    def sexp(self):
        return parse(['certificate', self.certs.sexp()])

def newCertificate(certs):
    return Certificate(certs)

class CertificateRequest(Message):
    # XXX not clear if we want to add the certificate_authorities
    # slot.   I guess this would just be a list of keys...
    def sexp(self):
        return parse(['certificate-request'])

class ServerHelloDone(Message):
    def sexp(self):
        return parse(['server-hello-done'])

class PreMasterSecret(Message):
    # not, strictly speaking, a message, but an object that is carried 
    # around in a message
    RANDOM_SIZE = 46
    
    def __init__(self, ver, rand):
        self.ver = ver
        self.rand = rand

    def sexp(self):
        return parse(['pre-master-secret', self.ver, self.rand.sexp()])

def newPreMasterSecret():
    return newRandom(PreMasterSecret.RANDOM_SIZE)    

class ClientKeyExchange(Message):
    # always contains the RSA EncryptedPreMasterSecret because we're
    # only doing RSA

    def __init__(self, cipher):
        """cipher contains the PreMasterSecret encrypted with the
        server's public key"""
        self.cipher = cipher

    def decryptPreMasterSecret(self, key):
	plain = key.decrypt(self.cipher)
	return eval(spkilib.sexp.parse(plain))

    def sexp(self):
        return parse(['client-key-exchange', self.cipher])
        
def newClientKeyExchange(sess, _pms):
    # XXX I guess public and private keys need to have basic
    # encrypt/decrypt methods
    pms = PreMasterSecret('0', _pms)
    cipher = sess.encryptForServer(pms.sexp().encode_canonical())
    return ClientKeyExchange(cipher)

class CertificateVerify(Message):
    # contains a SPKI signature object, which is a bit different than
    # the TLS spec's signature style
    def __init__(self, sig):
        self.sig = sig
    
    def sexp(self):
        return parse(['certificate-verify', self.sig.sexp()])

def newCertificateVerify(key, msgs):
    """Create a CV message using key to sign all the msgs"""
    canon = []
    for msg in msgs:
        canon.append(msg.sexp().encode_canonical())
    buf = string.join(canon, '')
    return CertificateVerify(key.sign(buf))

class Finished(Message):
    def __init__(self, verify):
        self.verify = verify
    def sexp(self):
	return parse(['finished', self.verify])

def newFinished(data):
    # there lot's of stuff that goes in a finished message, probably
    # makes sense to come back to it after the protocol structures are 
    # more in place
    return Finished(data)

class CloseNotify(Message):
    def sexp(self):
        return parse(['close-notify'])

# XXX need all the error messages
class Error(Message):
    # for now, just a single bogus error message
    def __init__(self, msg):
        self.msg = msg
    def sexp(self):
        return parse(['error', self.msg])

class Data(Message):
    """Protected application payload data"""
    # XXX This may be completely bogus because the hmac is performed
    # on the data only and not on the data + length + version
    def __init__(self, data, mac):
	self.data = data
	self.mac = mac

    def sexp(self):
	return parse(['data', self.data, self.mac]) 

class CipheredData(Message):
    def __init__(self, data):
	self.data = data

    def sexp(self):
	return parse(['ciphered-data', self.data])

def pad(buf):
    n = len(buf) % 8
    n = 8 - n
    if n == 0:
	n = 8
    return buf + str(n) * n

def unpad(buf):
    n = int(buf[-1])
    return buf[:-n]

class Session:
    """Tracks state of TTLS session"""
    
    def __init__(self, ssock, isClient):
	"""Create new session
	
	Arugments:
	ssock -- a SpkiSocket object
	isClient -- boolean, true if this is client side
	"""
	self.sock = ssock
	self.isClient = isClient

	# used by the handshake protocol
	self.__msgs = []
        self.client_random = None
        self.server_random = None
        self.pre_master_secret = None
	self.serverKey = None
	self.clientKey = None

	# used during connection operation
	self.read_seqno = 0L
	self.write_seqno = 0L

	# stuff the might be variable in a TLS-style protocol, but not 
	# in TTLS.
	# the MAC is HMAC_MD5: 16 bytes
	# the cipher is 3DES: 2 x 24 bytes
	# the IV adds: 2 x 8 bytes
	self.sizeMAC = 16
	self.sizeCipher = 24
	self.sizeIV = 8

	# XXX what 'bout flush?
	self.compress = zlib.compress
        self.decompress = zlib.decompress
	self.hmac = hmac.HMAC(MD5).hash

    def close(self):
        msg = CloseNotify()
        # XXX should this alert be sent encrypted, etc?  probably...
        self.sock.send_sexp(msg)
        self.sock.close()

    # the next two do the compression, mac, cipher

    def send(self, buf):
	data = self.newData(buf)
	enc = self.newCipheredData(data)
	self.write_seqno = self.write_seqno + 1
	self.sock.send_sexp(enc)

    def recv(self):
	sexp = self.sock.recv_sexp()
	if sexp is None:
	    return
	msg1 = eval(sexp)

        if isinstance(msg1, CloseNotify):
            raise EOFError
        
	if not isinstance(msg1, CipheredData):
	    raise RuntimeError, "unexpected message:", msg1

	msg2 = self.decryptCipheredData(msg1)
	if not isinstance(msg2, Data):
	    raise RuntimeError, "unexpected message:", msg2

	buf = self.getData(msg2)
	self.read_seqno = self.read_seqno + 1
	return buf

    def newCipheredData(self, data):
	buf = pad(data.sexp().encode_canonical())
	if self.isClient:
	    cipher = self.client_cipher
	else:
	    cipher = self.server_cipher
	return CipheredData(cipher.encrypt(buf))

    def decryptCipheredData(self, msg):
	if self.isClient:
	    cipher = self.server_cipher
	else:
	    cipher = self.client_cipher
	buf = unpad(cipher.decrypt(msg.data))
	return eval(spkilib.sexp.parse(buf))

    def getData(self, msg):
	# check the MAC
	if self.isClient:
	    secret = self.server_MAC_secret
	else:
	    secret = self.client_MAC_secret
	expectedMAC = self.makeMAC(secret, self.read_seqno, msg.data)
	if expectedMAC != msg.mac:
	    raise RuntimeError, "MAC failed"
	return self.decompress(msg.data)

    def newData(self, buf):
	shrunk = self.compress(buf)
	if self.isClient:
	    secret = self.client_MAC_secret
	else:
	    secret = self.server_MAC_secret
	mac = self.makeMAC(secret, self.write_seqno, shrunk)
	return Data(shrunk, mac)

    def makeMAC(self, secret, seqno, buf):
	seqstr = long_to_bytes(seqno)
	buf = seqstr + buf
	mac = self.hmac(secret, [buf])[0]
## 	print "HMAC(%s, %s) = %s" % (repr(secret), repr(buf),
## 				     repr(mac))
	return mac

    # the next to are helpers to record all messages for later use in
    # handshake protocol  

    def send_sexp(self, msg):
	self.__msgs.append(msg.sexp())
	self.sock.send_sexp(msg)

    def read_sexp(self):
	msg = self.sock.read_sexp()
	self.__msgs.append(msg)
	return msg

    # set up the session state during the handshake

    def encryptForServer(self, plain):
	return self.serverKey.encrypt(plain)

    def setServerKey(self, key):
	self.serverKey = key

    def setClientKey(self, key):
	self.clientKey = key

    def setClientRandom(self, rand):
        self.client_random = rand.rand

    def setServerRandom(self, rand):
        self.server_random = rand.rand

    def setPreMasterSecret(self, rand):
        self.pre_master_secret = rand.rand

    def verifyClient(self, sig, what):
	return self.clientKey.verify(sig, what)

    def getMessages(self, skip=0):
	"""Get a single buffer containing all previous messages"""
	canon = []
	if skip:
	    msgs = self.__msgs[:-1]
	else:
	    msgs = self.__msgs
	for msg in msgs:
	    canon.append(msg.encode_canonical())
	return string.join(canon, '')

    def checkVerifyData(self, data):
	"""Verify the other party's verify_data value"""
	if self.isClient:
	    label = "server finished"
	else:
	    label = "client finished"
	# when server is verifying, it needs to ignore the last
	# message sent, because the client had not seen the
	# message when it computed its verify_data
	buf = self.getMessages(skip=1)
	    
	expected = self.__doVerifyData(label, buf)
	return expected == data

    def makeVerifyData(self):
	if self.isClient:
	    label = "client finished"
	else:
	    label = "server finished"
	buf = self.getMessages()
	return self.__doVerifyData(label, buf)

    def __doVerifyData(self, label, buf):
	md5 = MD5.MD5(buf).digest()
	sha = SHA.SHA(buf).digest()
## 	print "PRF(%s, %s, %s)" % (repr(self.master_secret),
## 				   repr(label),
## 				   repr(md5 + sha))
	verify = PRF(self.master_secret, label, md5 + sha, 12)
	return verify

    def makeMasterSecret(self):
	secret = PRF(self.pre_master_secret, "master secret",
		     self.client_random + self.server_random,
		     48)
	self.master_secret = secret
	# XXX how to guarantee that this string is zapped? what about
	# the mesages if self.__msgs?  elsewhere?  
	del self.pre_master_secret

    # do the key setup
    def makeKeys(self):
	size = (self.sizeMAC + self.sizeCipher + self.sizeIV) * 2
	block = PRF(self.master_secret, "key expansion",
		    self.client_random + self.server_random,
		    size)
	# Note RFC 2246 calls these vars client_write_MAC_secret and
	# the like, but I'm skipping the 'write' because there is no
	# 'read'
	f = cStringIO.StringIO(block)
	self.client_MAC_secret = f.read(self.sizeMAC)
	self.server_MAC_secret = f.read(self.sizeMAC)
	self.client_key = f.read(self.sizeCipher)
	self.server_key = f.read(self.sizeCipher)
	self.client_IV = f.read(self.sizeIV)
	self.server_IV = f.read(self.sizeIV)
	assert f.tell() == len(block)

	self.client_cipher = DES3.new(self.client_key, DES3.CBC,
				      self.client_IV)
	self.server_cipher = DES3.new(self.server_key, DES3.CBC,
				      self.server_IV) 
    
# below here are some cryptographic operations need for a ttls protocol
class HMACExpander:
    """P_hash function defined in Section 5 of RFC 2246:

    [W]e define a data expansion function, P_hash(secret, data)
    which uses a single hash function to expand a secret and seed into an
    arbitrary quantity of output:

        P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                               HMAC_hash(secret, A(2) + seed) +
                               HMAC_hash(secret, A(3) + seed) + ...

    Where + indicates concatenation.

    A() is defined as:
        A(0) = seed
        A(i) = HMAC_hash(secret, A(i-1))
    """
    def __init__(self, hash):
        self.__hmac = hmac.HMAC(hash)
        self.__hashSize = hash.digestsize

    def P_hash(self, secret, seed, bytesNeeded):
        # Note that the HMAC interface is confusing because it
        # operates on a secret and a sequence of strings, where one
        # might expect the second arg to be a single string.
        hashes = []
        a = seed # A(0)
        for i in range(bytesNeeded / self.__hashSize + 1):
            a = self.__hmac.hash(secret, [a])[0]
            # A(i+1) = HMAC(secret, A(i))
            chunk = self.__hmac.hash(secret, [a + seed])[0]
            hashes.append(chunk)
        buf = string.join(hashes, '')
        return string.join(hashes, '')[:bytesNeeded]

P_MD5 = HMACExpander(MD5).P_hash
P_SHA = HMACExpander(SHA).P_hash

def PRF(secret, label, seed, bytesNeeded):
    """A pseudo-random function defined by Section 5 of RFC 2246

    The PRF is then defined as the result of mixing the two pseudorandom
    streams by exclusive-or'ing them together.

        PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
                                   P_SHA-1(S2, label + seed);

    S1 and S2 are the two halves of the secret and each is the same
    length. S1 is taken from the first half of the secret, S2 from the
    second half. Their length is created by rounding up the length of the
    overall secret divided by two; thus, if the original secret is an odd
    number of bytes long, the last byte of S1 will be the same as the
    first byte of S2.

        L_S = length in bytes of secret;
        L_S1 = L_S2 = ceil(L_S / 2);
    

    The label is an ASCII string. It should be included in the exact form
    it is given without a length byte or trailing null character.  For
    example, the label "slithy toves" would be processed by hashing the
    following bytes:

        73 6C 69 74 68 79 20 74 6F 76 65 73

    Note that because MD5 produces 16 byte outputs and SHA-1 produces 20
    byte outputs, the boundaries of their internal iterations will not be
    aligned; to generate a 80 byte output will involve P_MD5 being
    iterated through A(5), while P_SHA-1 will only iterate through A(4).

    """
    ls1 = len(secret) / 2 + len(secret) % 2
    s1 = secret[:ls1]
    s2 = secret[-ls1:]

    # to perform the XOR, we need the bytes as ints
    md5 = map(ord, P_MD5(s1, label + seed, bytesNeeded))
    sha = map(ord, P_SHA(s2, label + seed, bytesNeeded))
    bytes = []
    for i in range(bytesNeeded):
        b = md5[i] ^ sha[i]
        bytes.append(b)
    return string.join(map(chr, bytes), '')

_evaluator = spkilib.spki.Evaluator(globals(), spkilib.spki.__dict__)
eval = _evaluator.eval


def test():
    """PRF test vector

    From: Rene Eberhard <rene.eberhard@entrust.com> 
    To: "IETF Transport Layer Security WG" <ietf-tls@lists.consensus.com> 
    Subject: PRF Testvector for the standard 
    Date: Mon, 5 Oct 1998 03:33:57 -0400 

    I suggest the introduction of a testvector that results from
    the MD5 hash from a 104 Byte PRF output.
    I choosed 104 bytes because:
     - There's a similar example in '6.3. Key calculation'
     - 104 Bytes is neither a multiple of 16 bytes nor of 20 bytes.
       Thus discarding is also tested.
     - To produce 104 bytes at least 6 rounds are needed.

    out[104]       = PRF(secret, label, seed)
    PRF Testvector = MD5(out[104])
                   = CD 7C A2 CB 9A 6A 3C 6F 34 5C 46 65 A8 B6 81 6B

    The following parameters are passed to PRF:
      - secret: 48 Byte 0xab
        Length of pre_master_secret
      - label : 14 Byte "PRF Testvector"
      - seed  : 64 Byte 0xcd
        Length of client_random + server_random

    Below the whole 104 bytes. These are only attached for verification.
    They sould not appear in the TLS spec.

    0x00  D3 D4 D1 E3 49 B5 D5 15 04 46 66 D5 1D E3 2B AB
    0x10  25 8C B5 21 B6 B0 53 46 3E 35 48 32 FD 97 67 54
    0x20  44 3B CF 9A 29 65 19 BC 28 9A BC BC 11 87 E4 EB
    0x30  D3 1E 60 23 53 77 6C 40 8A AF B7 4C BC 85 EF F6
    0x40  92 55 F9 78 8F AA 18 4C BB 95 7A 98 19 D8 4A 5D
    0x50  7E B0 06 EB 45 9D 3A E8 DE 98 10 45 4B 8B 2D 8F
    0x60  1A FB C6 55 A8 C9 A0 13
    """

    expected_hash = '\315|\242\313\232j<o4\\Fe\250\266\201k'
    
    secret = chr(0xab) * 48
    label = "PRF Testvector"
    seed = chr(0xcd) * 64
    result = PRF(secret, label, seed, 104)
    hash = MD5.MD5(result).digest()
    assert expected_hash == hash, "PRF testvector failed"

if __name__ == "__main__":
    test()

