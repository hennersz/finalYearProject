"""Library for talking to an Entropy Gathering Daemon (egd)

The egd can or is used by GnuPG to generate high-quality random data.
EGD communicates with clients over a Unix domain socket.  It uses a
weird binary protocol.

The commands are as follows:
chr(0) -> returns 32-bit number (network byte-order)
chr(1) + chr(N) -> returns up to N bytes of random data
chr(2) + chr(N) -> returns N bytes of random data (possibly blocking)
chr(3) + XXX -> looks like a way to add entropy
chr(4) -> returns pid as string

he return values for 1,2,&4 seem to prepend the length of the string
to the returned string.
"""

import socket
import struct

class EGD:
    """Client-library for communicating with an EGD server"""
    
    def __init__(self, path):
        """Creates an EGD instance connected to Unix domain socket path"""
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)

    # commands are
    AVAILABLE_ENTROPY = chr(0)
    RANDOM_BYTES = chr(1)
    RANDOM_BYTES_SYNC = chr(2)
    GETPID = chr(4)

    def getAvailableEntropy(self):
        """Returns the number of bits of entropy currently available"""
        self.sock.send(self.AVAILABLE_ENTROPY)
        buf = self.sock.recv(4)
        return struct.unpack("!l", buf)[0]

    def getRandomBytes(self, num):
        """Get up to num bytes of random data

        num must be <= 255
        """
        if num > 255:
            raise ValueError, "can only ask for 0 to 255 bytes"
        self.sock.send(self.RANDOM_BYTES + chr(num))
        buf = self.sock.recv(1 + num)
        buflen = ord(buf[0]) + 1
        while buflen != len(buf):
            buf = buf + self.sock.recv(num)
        return buf[1:]
        
    def getRandomBytesSync(self, num):
        """Get exactly num bytes of data, blocking if necessary

        num must be <= 255
        """
        # XXX this method doesn't seem to work right...
        if num > 255:
            raise ValueError, "can only ask for 0 to 255 bytes"
        self.sock.send(self.RANDOM_BYTES_SYNC + chr(num))
        buf = self.sock.recv(1 + num)
        buflen = ord(buf[0]) + 1
        while buflen != len(buf):
            buf = buf + self.sock.recv(num)
        return buf[1:]
        
    def getPID(self):
        """Get the pid of the entropy daemon"""
        self.sock.send(self.GETPID)
        buf = self.sock.recv(8)
        buflen = ord(buf[0]) + 1
        while buflen != len(buf):
            buf = buf + self.sock.recv(8)
        return int(buf[1:])

    # XXX haven't implemented the chr(3) command, because I'm not sure 
    # how it's supposed to work

def test(path):
    import time
    
    egd = EGD(path)
    print "will attempt to empty the random pool (to less than 8 bits)"
    amt = egd.getAvailableEntropy()
    print "contains %d bits" % amt
    while amt > 0:
        buf = egd.getRandomBytes(16)
        if not buf:
            check = egd.getAvailableEntropy()
            print "only %d bits remain" % check
            break
        amt = amt - len(buf) * 8
        check = egd.getAvailableEntropy()
        # The number could go up while we're running, because more
        # entropy gets added as time goes by
        delta = check - amt
        if delta:
            print "entropy pool grew by %d bits" % delta
            amt = check
        print "remaining entropy: %d bits" % amt

if __name__ == "__main__":
    test()


