#!/usr/bin/python3

import kplugs

with kplugs.Context() as context:
    kernel_func = r'''

def dyn_alloc(size):
    return new(size, 1) # enable the global flag

def dyn_free(ptr):
    pointer(ptr)
    delete(ptr)

def send_wait(data, flags, internal):
    buffer(data, 0x100)
    pointer(ptr)

    len = 0
    while data[len] and len < 0x100:
        len += 1
    ptr = new(len)
    KERNEL_memcpy(ptr, data, len);

    if internal:
        send(ptr, flags, "internal")
    else:
        send(ptr, flags)

def recv_wait(flags, ret):
    pointer(ptr)
    array(ret, 2)
    ret[0] = recv(ptr, flags)
    ret[1] = ptr

def internal():
    pointer(ptr)
    recv(ptr) # will block
    print ("%s" % (ptr))
'''

    plug = context.Plug()
    mem = context.Mem()
    alloc, free, send, recv, internal = plug.compile(kernel_func)
    while True:
        data = input("> ").strip().split()
        if len(data) == 0:
            continue

        if data[0] == "exit":
            break

        elif data[0] == "send_user":
            nonblock = False
            if int(data[2]):
                nonblock = True
            recv.send(data[1], nonblock)

        elif data[0] == "recv_user":
            nonblock = False
            if int(data[2]):
                nonblock = True
            print(send.recv(int(data[1]), nonblock).decode())

        elif data[0] == "send_kernel":
            flags = 0
            if int(data[2]):
                flags |= kplugs.Function.PARAM_NONBLOCK
            send(data[1], flags, int(data[3]))

        elif data[0] == "recv_kernel":
            flags = kplugs.Function.PARAM_GLOBAL
            if int(data[1]):
                flags |= kplugs.Function.PARAM_NONBLOCK
            ret = bytearray(plug.word_size * 2)
            recv(flags, ret)
            n, data = plug.world.unpack(plug.world.form*2, bytes(ret))
            print(mem[data:data+n].decode())
            free(data)

        elif data[0] == "internal":
            internal()

        else:
            print ("Unknown command")

