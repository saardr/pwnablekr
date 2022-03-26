#!/usr/bin/env python3

from pwn import *

random_res = 1804289383
target = 0xdeadbeef

result = target ^ random_res
sol = str(result)

ssh_tunnel = ssh(user="random", host="pwnable.kr", port=2222, password="guest")
io = ssh_tunnel.run('./random')
io.sendline(sol)
io.interactive()
