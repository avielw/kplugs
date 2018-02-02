#!/usr/bin/python2

import kplugs
import struct

try:
    plug = kplugs.Plug(ip='127.0.0.1')
    mem = kplugs.Mem(ip='127.0.0.1')
    sym = kplugs.Symbol(ip='127.0.0.1')
    caller = kplugs.Caller(ip='127.0.0.1')
    hook = kplugs.Hook(ip='127.0.0.1')

    jiffies = sym["jiffies"] # Getting the current time
    kernel_buf = mem.alloc(kplugs.WORD_SIZE) # Allocating a buffer in kernel space
    mem[kernel_buf] = mem[jiffies:jiffies+kplugs.WORD_SIZE] # Copying the current time to our kernel buffer
    print "The current time is: ", struct.unpack("P", mem[kernel_buf:kernel_buf+kplugs.WORD_SIZE])[0]

    kernel_func = r'''

def my_hook(kp, regs):
    print "The registers are stored in %p" % regs
    return 0
'''
    my_hook = plug.compile(kernel_func)[0]
    hook.hook("vmalloc", my_hook) # Hook the kernel function - vmalloc
    p = caller["vmalloc"](0x100) # Execute the kernel function - vmalloc. the hook should be executed
    caller["vfree"](p)
    hook.unhook(my_hook)

finally:
    kplugs.release_kplugs()
