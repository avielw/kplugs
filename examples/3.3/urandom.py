#!/usr/bin/python3

import kplugs
import struct
import codecs

with kplugs.Context() as context:
    plug = context.Plug()
    caller = context.Caller()
    mem = context.Mem()
    sym = context.Symbol()
    ws  = plug.word_size

    fops = sym["urandom_fops"]
    read = sym["urandom_read"]
    print("urandom_fops: 0x%x" % (fops))
    print("urandom_read: 0x%x" % (read))
    data = mem[fops :fops + 20*ws]
    over_addr = 0
    for i in range(0, 20*ws, ws):
        d = plug.world.unpack(plug.world.form, data[i:i+ws])[0]
        if d == read:
            over_addr = fops + i
            break

    if not over_addr:
        raise Exception("Could not find read function")

    print("function pointer address: 0x%x" % (over_addr))
    my_read = plug.compile('''
ANONYMOUS('my_read')
def my_read(file, buf, nbytes, ppos):
    array(file, 0x20)
    pointer(orig_read)
    pointer(msg)

    orig_read = %d
    try:
        send(file)
        recv(msg)
    except:
        pass
    return orig_read(file, buf, nbytes, ppos)
''' % (read,))[0]

    try:
        if caller["memory_poke_kernel_address"](over_addr, my_read.addr):
            raise Exception("Could not poke kernel address")
        while True:
            print(codecs.encode(my_read.recv(0x100), 'hex').decode())
            my_read.send('a')
    finally:
        caller["memory_poke_kernel_address"](over_addr, read)


