from pisces import ttls
from pisces.spkilib import sexpsocket

from SocketServer import ThreadingTCPServer, BaseRequestHandler
import socket
import string
import exceptions

class ProtocolError(exceptions.Exception):
    pass

class MyServer(ThreadingTCPServer):
    def __init__(self, server_address, RequestHandlerClass, key, opts): 
        ThreadingTCPServer.__init__(self, server_address,
                                    RequestHandlerClass)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                               1)
        self.key = key
        self.opts = opts
        self.initSecurity()
        
    def initSecurity(self):
        self.certs = self.opts.getChain(self.key)
        self.opts.store.close()

    def serve_forever(self):
        while 1:
            print "handle_request()"
            self.handle_request()

class TTLSRequestHandler(BaseRequestHandler):
    """The BaseRequestHandler will create three instance variables:
    request -- a socket object
    client_address -- a name, port tuple
    server -- the SocketServer instance
    """

    VERBOSE = 1

    def setup(self):
        self.request = sexpsocket.SexpSocket(self.request)

    def handle(self):
	self.sess = ttls.Session(self.request, 0)
        try:
            if self.VERBOSE:
                print self.request
                print self.client_address
                print self.server
            self.do_handshake()
	    self.sess.makeKeys()
	    # just a simple echo server
            try:
                while 1:
                    buf = None
                    while buf is None:
                        buf = self.sess.recv()
                    self.sess.send(buf)
            except EOFError:
                self.sess.close()
        except ProtocolError, msg:
            self.request.send_sexp(ttls.Error(msg))
	self.request.close()

    def do_handshake(self):
        cli = ttls.eval(self.sess.read_sexp())
        if not isinstance(cli, ttls.ClientHello):
            raise ProtocolError, "expected client-hello"
        self.sess.setClientRandom(cli.rand)
        
        svr = ttls.newServerHello()
        self.sess.setServerRandom(svr.rand)
        self.sess.send_sexp(svr)

        msg = ttls.newCertificate(self.server.certs)
        self.sess.send_sexp(msg)
        msg = ttls.CertificateRequest()
        self.sess.send_sexp(msg)
        msg = ttls.ServerHelloDone()
        self.sess.send_sexp(msg)

	# since we sent a CertReq message, we must get one back
	msg = ttls.eval(self.sess.read_sexp())
	if not isinstance(msg, ttls.Certificate):
	    raise ProtocolError, "expected certificate message"
	cliPrin = msg.getPrincipal()
	self.sess.setClientKey(self.server.opts.lookupKey(cliPrin))

	# get the client-key exchange
	# XXX don't forget about the Bleichenbacher attack: if
	# something goes wrong with the PreMasterSecret, use invent a
	# new one instead of raising an error
	msg = ttls.eval(self.sess.read_sexp())
	secret = msg.decryptPreMasterSecret(self.server.key.priv)
	self.sess.setPreMasterSecret(secret.rand)

	# get the cert-verify message
	buf = self.sess.getMessages()
	msg = ttls.eval(self.sess.read_sexp())
	if not self.sess.verifyClient(buf, msg.sig):
	    raise ProtocolError, "bad certificate-verify message"

	# there is no change-cipher-spec message here, because we
	# always use the same cipher 

	self.sess.makeMasterSecret()
	msg = ttls.eval(self.sess.read_sexp())
	if not self.sess.checkVerifyData(msg.verify):
	    raise ProtocolError, "bad verify_data"
	msg = ttls.newFinished(self.sess.makeVerifyData())
        self.sess.send_sexp(msg)
        
def main():
    opts = ttls.parseopt(0)
    server = MyServer((opts.host, opts.port), TTLSRequestHandler,
                      opts.getKeyPair(), opts) 
    server.serve_forever()

if __name__ == "__main__":
    main()
