#!/usr/bin/python3

#!/usr/bin/python

import kplugs

try:
    kernel_func = r'''

def dyn_alloc(size):
    return new(size, 1) # enable the global flag

def dyn_free(ptr):
    pointer(ptr)
    delete(ptr)

def send_wait(data, nonblock, internal):
    buffer(data, 0x100)
    pointer(ptr)

    len = 0
    while data[len] and len < 0x100:
        len += 1
    ptr = new(len)
    KERNEL_memcpy(ptr, data, len);

    if nonblock:
        if internal:
            send(ptr, 1, "internal")
        else:
            send(ptr, 1)
    else:
        if internal:
            send(ptr, 0, "internal")
        else:
            send(ptr)

def recv_wait(nonblock, ret):
    pointer(ptr)
    array(ret, 2)
    if nonblock:
        ret[0] = recv(ptr, 1, 1)
    else:
        ret[0] = recv(ptr, 0, 1)

    ret[1] = ptr

def internal():
    pointer(ptr)
    recv(ptr) # will block
    print ("%s" % (ptr))
'''

    plug = kplugs.Plug()
    mem = kplugs.Mem()
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
            send.recv(data[1], nonblock)

        elif data[0] == "send_kernel":
            send(data[1], int(data[2]), int(data[3]))

        elif data[0] == "recv_kernel":
            ret = bytearray(plug.word_size * 2)
            recv(int(data[1]), ret)
            n, data = plug.world.unpack(plug.world.form*2, bytes(ret))
            print(mem[data:data+n].decode())
            free(data)

        elif data[0] == "internal":
            internal()

        else:
            print ("Unknown command")

finally:
    kplugs.release_kplugs()
