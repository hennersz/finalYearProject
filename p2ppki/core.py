import asyncore
import asynchat

class Handler(asynchat.async_chat):
    def __init__(self, socket):
        asynchat.async_chat.__init__(self, sock=socket)
        self.inputBuffer = []
        self.outputBuffer = b""
        self.set_terminator(b"\n")
    
    def collect_incoming_data(self, data):
        self.inputBuffer.append(data)
    
    def found_terminator(self):
        self.outputBuffer = b"".join(self.inputBuffer)
        self.outputBuffer += b"\n"        
        self.push(self.outputBuffer)
        self.close_when_done()

class Listener(asyncore.dispatcher):
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket()
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)

    def handle_accepted(self, sock, addr):
        print('Incoming connection from %s' % repr(addr))
        handler = Handler(sock)


server = Listener('localhost', 1234)

try:
    asyncore.loop() 
except KeyboardInterrupt:
    pass

server.close()
