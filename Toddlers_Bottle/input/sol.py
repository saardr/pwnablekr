#!/usr/bin/env python

from pwn import *
import os
import socket

# stage1
arg = ['a' for i in range(100)]
arg[0] = '/home/input2/input'
arg[0x41] = '\x00'
arg[0x42] = '\x20\x0a\x0d'
arg[0x43] = '1338'

# stage2
open("wstdin", "w").write("\x00\x0a\x00\xff")
open("wstderr", "w").write("\x00\x0a\x02\xff")
open("\x0a", "w").write("\x00"*4)

print os.getcwd()
p = process(arg, stdin=open("wstdin"), stderr=open("wstderr"),
env={"\xde\xad\xbe\xef":"\xca\xfe\xba\xbe"}, cwd=os.getcwd())
print p.recv()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 1338))
s.send("\xde\xad\xbe\xef")

print p.recv()
print p.recv()
p.close()
