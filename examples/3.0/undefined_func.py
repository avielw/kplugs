#!/usr/bin/python3

import kplugs

try:
    kernel_func = r'''
STATIC("my_helper")

def my_function():
    try:
        my_helper()
        print("OK")
    except word as err:
        print("Exception number: %d" % -err)
        raise err

def my_helper():
	KERNEL_undefined_function()

'''

    plug = kplugs.Plug()
    my_function = plug.compile(kernel_func)[0]
    my_function()

finally:
    kplugs.release_kplugs()
