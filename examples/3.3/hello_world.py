#!/usr/bin/python3

import kplugs

with kplugs.Context() as context:
    kernel_func = r'''

def hello_world(string):
    buffer(string, 0x100)
    print("%s" % string)
'''

    plug = context.Plug()
    hello_world = plug.compile(kernel_func)[0]
    hello_world("Hello World!")

