#!/usr/bin/python2

import kplugs
import os

try:
    kernel_func = r'''

def send_recv(string):
    buffer(string, 10)
    pointer(ptr)
    send(string, 'send_recv_worker')
    recv(ptr)
    send(ptr)

def send_recv_worker():
    pointer(ptr)
    i = recv(ptr)
    j = 0
    while j < i:
        ptr[j] &= ~0x20
        j += 1
    send(ptr, 'send_recv')
'''

    plug = kplugs.Plug()
    send_recv, send_recv_worker = plug.compile(kernel_func)
    if os.fork() == 0:
        send_recv_worker()
        exit(0)

    send_recv('AaBbCcDdEe')
    print send_recv.recv(0x100)
finally:
    kplugs.release_kplugs()
