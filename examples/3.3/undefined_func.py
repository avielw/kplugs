#!/usr/bin/python3

import kplugs

with kplugs.Context() as context:
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

    plug = context.Plug()
    my_function = plug.compile(kernel_func)[0]
    my_function()

