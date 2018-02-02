#!/usr/bin/python2

import kplugs
import ctypes

try:
    kernel_func = r'''
BUFFER_SIZE = 0x10
ERROR_POINT = 12 # taken from types.h

def get_initramfs(user_initram):
    buffer(user_initram, BUFFER_SIZE)
    pointer(initram)
    pointer(sizeptr)

    initram = KERNEL_kallsyms_lookup_name("__initramfs_start")
    sizeptr = KERNEL_kallsyms_lookup_name("__initramfs_size")
    if initram == 0 or sizeptr == 0:
        raise ERROR_POINT

    size = DEREF(sizeptr)
    if size < 0 or size > BUFFER_SIZE:
        size = BUFFER_SIZE
    KERNEL_memcpy(user_initram, initram, size)
    return size
'''

    plug = kplugs.Plug()
    buf = ctypes.c_buffer(0x10)
    get_initramfs = plug.compile(kernel_func)[0]
    size = get_initramfs(ctypes.addressof(buf))
    print "The initramfs starts with: '%s'" % (buf.raw[:size].encode("hex"), )

finally:
    kplugs.release_kplugs()

