#!/usr/bin/env python3

from pwn import *

addr = "pwnable.kr"
port = 9007
RUN_COUNT = 100

r = remote(addr, port)

def read_until(s):
    res = r.recvuntil(s).decode()
    # print(res)
    return res


def get_line():
    res = r.recvline().decode()
    # print(res)
    return res


def read_prologue():
    read_until("3 sec... -")
    get_line()
    get_line()

def get_N_and_C():
    N_s, C_s = get_line().split()
    N = int(N_s[2:])
    C = int(C_s[2:])
    return N, C


def test_indexes(indexes):
    s = ' '.join(str(num) for num in indexes)
    # print(s)
    r.sendline(s)
    res = get_line()
    try:
        weight = int(res)
    except:     # correct result
        weight = 9
    return weight


def find_bad_coin():
    N, C = get_N_and_C()

    l, r = 0, N-1

    for i in range(C+1):
        mid = (l + r)//2
        weight = test_indexes(range(l, mid+1))
        if weight % 2 == 0:                 # fake coin aint in this pile
            l = mid+1
        else:
            r = mid


read_prologue()

for i in range(RUN_COUNT):
    find_bad_coin()
    print(i)

print(r.recv())

# b1NaRy_S34rch1nG_1s_3asy_p3asy