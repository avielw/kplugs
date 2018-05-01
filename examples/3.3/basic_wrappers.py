#!/usr/bin/python3

import kplugs
import struct

with kplugs.Context() as context:
    plug = context.Plug()
    mem = context.Mem()
    sym = context.Symbol()
    caller = context.Caller()
    hook = context.Hook()

    jiffies = sym["jiffies"] # Getting the current time
    kernel_buf = mem.alloc(kplugs.WORD_SIZE) # Allocating a buffer in kernel space
    mem[kernel_buf] = mem[jiffies:jiffies+kplugs.WORD_SIZE] # Copying the current time to our kernel buffer
    print("The current time is: ", struct.unpack("P", mem[kernel_buf:kernel_buf+kplugs.WORD_SIZE])[0])

    kernel_func = r'''

def my_hook(kp, regs):
    print("The registers are stored in 0x%lx" % regs)
    return 0
'''
    my_hook = plug.compile(kernel_func)[0]
    hook.hook("vmalloc", my_hook) # Hook the kernel function - vmalloc
    p = caller["vmalloc"](0x100) # Execute the kernel function - vmalloc. the hook should be executed
    caller["vfree"](p)
    hook.unhook(my_hook)

