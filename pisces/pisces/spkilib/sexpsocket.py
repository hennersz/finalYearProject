"""A socket for sending and receiving s-expressions"""

from socket import *
_socket =socket

from pisces import spkilib 

def socket(domain, type, proto=None):
    if proto is None:
        sock = _socket(domain, type)
    else:
        sock = _socket(domain, type, proto)
    return SexpSocket(sock)

class SexpSocket:

    SEXP_BUF_SIZE = 1024
    VERBOSE = 0
    
    def __init__(self, sock):
        self.sock = sock
        self.buf = ''

    def send_sexp(self, obj):
        """Encode a SPKI object and send it over the socket"""
        if self.VERBOSE:
            print "send"
            print spkilib.sexp.pprint(obj.sexp())
            print
        self.sock.send(obj.sexp().encode_canonical())

    def recv_sexp(self):
        """Read a full sexp from the socket if possible"""
	if self.buf:
	    sexp, self.buf = parseSexp(self.buf)
	    if sexp:
		return sexp
        buf = self.recv(self.SEXP_BUF_SIZE)
        if buf == '':
            raise EOFError
	self.buf = self.buf + buf
	sexp, self.buf = parseSexp(self.buf)
        return sexp

    def read_sexp(self):
        """Read a full sexp from the socket, blocking if necessary"""
        sexp = None
        try:
            while sexp is None:
                sexp = self.recv_sexp()
        except EOFError:
            return None
        if self.VERBOSE:
            print "read"
            print spkilib.sexp.pprint(sexp)
            print
        return sexp

    def __getattr__(self, attr):
        return getattr(self.sock, attr)

class ExtractableSexp(spkilib.sexp.SExp):
    """A subclass that makes it easier to read sexps off a socket

    The standard sexp parser assumes that it will be given a chunk of
    data the exactly contains an sexp.  It will either parse it or
    raise an exception.  It will also hide any data left over after
    the sexp is parsed.  None of this is very helpful when you're
    reading data coming in off a socket, because there's no guarantee
    that any particular recv call will contain exactly a complete
    sexp.

    It would probably be most helpful to have a parser that can be
    called with a partial sexp and then called again with more input.
    That's a little harder so I'm punting on it for now.
    """
    def _parse_canonical(self, canon):
        spkilib.sexp.SExp._parse_canonical(self, canon)
        self.__unparsed = canon[self._consumed + 1:]

    def getUnparsedData(self):
        return self.__unparsed

def parseSexp(buf):
    """Returns an Sexp object and a string of leftover data

    Tries to parse the buffer.  If it doesn't contain a full sexp, it
    will return None, buf.
    """
    try:
        s = ExtractableSexp(buf)
    except spkilib.sexp.ParseError:
        return None, buf
    else:
        return s, s.getUnparsedData()

