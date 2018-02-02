#!/usr/bin/python2

import kplugs
import os

try:
    kernel_func = r'''

def send_recv():
    pointer(ptr)
    i = recv(ptr)
    j = 0
    while j < i:
        ptr[j] &= ~0x20
        j += 1
    send(ptr)
'''

    plug = kplugs.Plug()
    send_recv = plug.compile(kernel_func)[0]
    if os.fork() == 0:
        send_recv()
        exit(0)

    send_recv.send('AaBbCcDdEe')
    a = send_recv.recv(0x100)
    print a
finally:
    kplugs.release_kplugs()
