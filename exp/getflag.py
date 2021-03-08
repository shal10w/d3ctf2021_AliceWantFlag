import socket
from elgamal import elgamal
from pubkey import server_pubkey , Alice_pubkey
from Crypto.Util.number import long_to_bytes , bytes_to_long
from Crypto.Cipher import AES
from gmpy2 import powmod , invert
import time
p ,q , g ,y = Alice_pubkey
AlicePasswd = b'547dd1ccc38'
def readdic():
    t1 = time.time()
    f = open('./data' , 'rb')
    data = f.read()
    f.close()
    dic = {}
    i = 0
    while i < len(data):
        c = data[i:i+5]
        i += 5
        listlen = data[i]
        i += 1
        alist = []
        for _ in range(listlen):
            temp = data[i:i+3]
            i+=3
            alist.append(temp)
        dic[c] = alist
    t2 = time.time()
    print(t2-t1)
    return dic

#dic = readdic()

def getdata(upper):
    dic = {}
    t1 = time.time()
    for i in range(upper):
        temp = powmod(i , q , p)
        temp = long_to_bytes(temp)[:5].rjust(5,b'\x00')
        if temp in dic:
            dic[temp].append(long_to_bytes(i).rjust(3 , b'\x00'))
        else:
            dic[temp] = [long_to_bytes(i).rjust(3 , b'\x00')]
    t2 = time.time()
    print(t2-t1)
    f = open('./data' , 'wb')
    print(len(dic))
    for i in dic:
        f.write(i)
        f.write(bytes([len(dic[i])]))
        for j in dic[i]:
            f.write(j)
    return dic

dic = getdata(2**23)
print('dic get!')

def elgdec(c):
    y1 , y2 = c
    c = powmod(y2 , q , p)
    solve = {}
    t1 = time.time()
    for i in range(1 , 2**20):
        temp = powmod(invert(i , p) , q , p) * c % p
        temp = long_to_bytes(temp)[:5].rjust(5 , b'\x00')
        if temp in dic:
            for j in dic[temp]:
                if powmod(i * bytes_to_long(j) , q , p) == c:
                    t2 =time.time()
                    print(t2 - t1)
                    return bytes_to_long(j) * i
    t2 =time.time()
    print(t2 - t1)
    return 0



def pad(m):
    m += bytes([16 - len(m) % 16] * (16 - len(m) % 16))
    return m

def unpad(m):
    return m[:-m[-1]]
    
class Alice:
    def __init__(self , ip , port):

        self.pubenc = elgamal(server_pubkey)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((ip, port))
    
    def _recv(self , bit = 1024):
        data = self.s.recv(bit)
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
        print(msg)
        if enc_key == b'':
            c = [int(i) for i in msg.split(b', ')]
            m = elgdec(c)
            return long_to_bytes(m)
        else:
            assert len(enc_key) == 16
            aes = AES.new(enc_key , AES.MODE_ECB)
            return unpad(aes.decrypt(msg))

    def main(self):
        firstmsg = self._recv()
        if firstmsg != b'1. signup  2.signin':
            return 0
        self._send('2')
        self._recv()
        self._send('Alice')
        self._recv()
        r = int(self._recv())
        userdata = long_to_bytes(bytes_to_long(AlicePasswd) ^ r)
        self.enc_send(userdata)
        self._recv()
        temp = self._recv(len(b"now let's communicate with this key\n"))

        print(temp)
        endkey = self.dec_recv()
        if endkey == b'\x00':
            return 0
        key = userdata + endkey
        self.enc_send(b'I am Alice, Please give me true flag' , enc_key= key)
        return self.dec_recv(enc_key= key)
    def close(self):
        self.s.close()


while 1:
    alice = Alice('47.100.0.15' , 10001)
    res = alice.main()
    alice.close()
    print(res)
    if res != 0:
        break