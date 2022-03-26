#!/usr/bin/env python3

from pwn import *

USER = "col"
HOST = "pwnable.kr"
PORT = 2222
PASSWORD = "guest"

hashcode = 0x21DD09EC

n = hashcode//5
last_n = n + hashcode % 5

b1 = p32(n)
b2 = p32(last_n)

payload = 4*b1 + b2

tunnel = ssh(user=USER, host=HOST, port=PORT, password=PASSWORD)
io = tunnel.process(['./col', payload])
print(io.recvline())

# FLAG: daddy! I just managed to create a hash collision :)
