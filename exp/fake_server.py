from elgamal import elgamal
import socketserver
from pubkey import Alice_pubkey , server_pubkey
import random
from os import urandom
from Crypto.Util.number import long_to_bytes , bytes_to_long
from Crypto.Cipher import AES
import socket
MENU = "1. signup  2.signin"
XOR = lambda s1,s2 :bytes([x1^x2 for x1 , x2 in zip(s1,s2)])
def pad(m):
    m += bytes([16 - len(m) % 16] * (16 - len(m) % 16))
    return m

def unpad(m):
    padlen = m[-1]
    for i in range(1 , padlen + 1):
        if m[-i] != m[-1]:
            return b''
    return m[:-m[-1]]

#server
ip = '0.0.0.0'
port = 10001
def readdata():
    f = open('./r' , 'r')
    Alice_passwd , bitnumber = eval(f.read())
    f.close()
    return Alice_passwd , bitnumber
def writedata(passwd , bitnumber):
    f = open('./r' , 'w')
    data = [passwd , bitnumber]
    f.write(str(data))
    f.close()

writedata(0 , 1)
class fake_Alice:
    def __init__(self):
        self.pubenc = elgamal(server_pubkey)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((ip, port))
    def _recv(self):
        data = self.s.recv(1024)
        return data.strip()

    def _send(self, msg):
        if isinstance(msg , str):
            msg = msg.encode()
        self.s.send(msg)

    def enc_send(self, msg , enc_key = b''):
        if enc_key == b'':
            y1 , y2 = self.pubenc.encrypt(bytes_to_long(msg))

            self._send(str(y1) + ', ' + str(y2))
        else:
            assert len(enc_key) == 16
            aes = AES.new(enc_key , AES.MODE_ECB)
            self._send(aes.encrypt(pad(msg)))
    
    def dec_recv(self,  enc_key = b''):
        msg = self._recv()
        if enc_key == b'':
            c = [int(i) for i in msg.split(b', ')]
            m = self.pridec.decrypt(c)
            return long_to_bytes(m)
        else:
            assert len(enc_key) == 16
            aes = AES.new(enc_key , AES.MODE_ECB)
            return unpad(aes.decrypt(msg))

    def signup(self , c):
        self._recv()
        self._send('shallow')
        self._recv()
        self._send(str(c[0]) + ', ' + str(c[1]))
        msg = self._recv()
        if msg[:4] == b'your':
            return 1
        else:
            self._send('1')
            self._recv()
            return 0
    def choose(self , choice):
        self._recv()
        self._send(str(choice))

    def main(self , c):
        Alice_passwd , bitnumber = readdata()
        while 1:
            print(long_to_bytes(Alice_passwd))
            new_c = [c[0], c[1] * 2**bitnumber % server_pubkey[0]]
            if c[1] == 0:
                exit(0)
            self.choose(1)
            if self.signup(new_c):
                Alice_passwd += 2**(88 - bitnumber)
                bitnumber += 1
                self.s.close()
                writedata(Alice_passwd , bitnumber)
                return 0
            else:
                bitnumber += 1

class fake_server(socketserver.BaseRequestHandler):
    def _recv(self):
        data = self.request.recv(1024)
        return data.strip()

    def _send(self, msg, newline=True):
        if isinstance(msg , bytes):
            msg += b'\n'
        else:
            msg += '\n'
            msg = msg.encode()
        self.request.sendall(msg)

    def enc_send(self, msg , usrid , enc_key = b''):
        if enc_key == b'':
            pubenc = self.pubkey[usrid]
            y1 , y2 = pubenc.encrypt(bytes_to_long(msg))
            self._send(str(y1) + ', ' + str(y2))
        else:
            assert len(enc_key) == 16
            aes = AES.new(enc_key , AES.MODE_ECB)
            self._send(aes.encrypt(pad(msg)))
    
    def dec_recv(self,  enc_key = b''):
        msg = self._recv()
        if enc_key == b'':
            c = [int(i) for i in msg.split(b', ')]
            m = self.prikey.decrypt(c)
            return long_to_bytes(m)
        else:
            assert len(enc_key) == 16
            aes = AES.new(enc_key , AES.MODE_ECB)
            return unpad(aes.decrypt(msg))
    def init_key(self):
        self.pubkey = {}
        self.pubkey[b'Alice'] = elgamal(Alice_pubkey)

    def signin(self):
        self._send('please give me your name')
        userid = self._recv()
        r = readdata()[0]
        self._send('please give me your passwd(encrypted and xored by r)')
        self._send(str(r))
        msg = self._recv()
        c = [int(i) for i in msg.split(b', ')]
        return c
    def handle(self):
        self.init_key()
        key = b''
        userid = ''
        self._send(MENU)
        choice = self._recv()
        c = self.signin()
        alice = fake_Alice()
        alice.main(c)
        print('done')
        self.request.close()
        return 0
class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 9001
    server = ForkedServer((HOST, PORT), fake_server)
    server.allow_reuse_address = True
    server.serve_forever()
 
