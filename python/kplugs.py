#!/usr/bin/python

from core import Plug, Function, WORD_SIZE
import ctypes
import struct

# we want it to be global because we don't want hooks callbacks to be freed under our feet in case that the module was not closed correctly
KPLUGS_OBJECTS = []

KPROBE_STRUCT_MAXSIZE = 0x100
KPROBE_STRUCT_ADDR    = 5 * WORD_SIZE
KPROBE_STRUCT_SYMBOL  = 6 * WORD_SIZE
KPROBE_STRUCT_HANDLER = 8 * WORD_SIZE


# unload kplugs - it's important unload the library or the computer may crash if you use hooks!
def release_kplugs():
	global KPLUGS_OBJECTS

	while len(KPLUGS_OBJECTS) != 0:
		KPLUGS_OBJECTS[0].release()


class Caller(object):
	def __init__(self, variable_argument = False):
		self._va = variable_argument
		self.plug = Plug()
		self.random_names = {}
		
	def _get_func(self, name, types):
		add = ''
		if self._va:
			add = 'VARIABLE_ARGUMENT("KERNEL_%s")' % (name, )

		args = ', '.join(["arg%d" % (i, ) for i in xrange(len(types))])
		decl = '\n\t'.join([types[i] % ("arg%d" % (i, ), ) for i in xrange(len(types))])

		func = '''
ANONYMOUS("caller_func")
%s

def caller_func(ret, %s):
	array(ret, 1)
	%s
	try:
		ret[0] = KERNEL_%s(%s)
	except exp:
		return exp
	return 0
''' % (add, args, decl, name, args)

		return self.plug.compile(func)[0]

	def _put_func(self, func):
		func.unload()

	def __getitem__(self, n):
		if not isinstance(n, str):
			raise Exception("Not a string")

		def caller(*args):
			ret = ctypes.c_buffer('\0'*WORD_SIZE)
			new_args = []
			types = []
			bufs = []
			for arg in args:
				if isinstance(arg, str):
					buf = ctypes.c_buffer(arg + '\0')
					types.append('buffer(%%s, %d)' % (len(arg) + 1, ))
					new_args.append(ctypes.addressof(buf))
					bufs.append(buf)
				else:
					types.append('word(%s)')
					new_args.append(arg)
			func = self._get_func(n, types)
			err = func(ctypes.addressof(ret), *new_args)
			self._put_func(func)
			if err:
				if err >= len(Plug.ERROR_TABLE):
					raise Exception("Error: 0x%x" % err)
				raise Exception(Plug.ERROR_TABLE[err])
			return struct.unpack("P", ret.raw[:WORD_SIZE])[0]

		return caller


# a memory class
class Mem(object):
	BLOCK_SIZE = 0x1000

	# allocate a kernel buffer
	def alloc(self, size, gfp = 0, dont_free = False):
		ret = self._caller["__kmalloc"](size, gfp)
		if ret == 0:
			raise Exception("Couldn't allocate memory")
		self._caller["memset"](ret, 0, size)
		if not dont_free:
			self._allocs.append(ret)
		return ret

	# free a kernel buffer
	def free(self, ptr):
		if self._allocs.count(ptr) == 0:
			raise Exception("This address don't belongs to the memory")
		self._allocs.remove(ptr)
		self._caller["kfree"](ptr)

	def __init__(self, default_pid = 0):
		global KPLUGS_OBJECTS

		self._pid = default_pid
		self._allocs = []
		self._caller = Caller()
		KPLUGS_OBJECTS.append(self)

	def __getitem__(self, n):
		buf = ctypes.c_buffer('\0'*Mem.BLOCK_SIZE)
		if isinstance(n, int) or isinstance(n, long):
			start = n
			stop = n + 1
			pid = self._pid
		else:
			start = n.start
			stop = n.stop
			pid = n.step
			if not start:
				start = 0
			if not stop:
				stop = start + 1
			if not pid:
				pid = self._pid

		ret = ""
		l = Mem.BLOCK_SIZE

		# copy the from memory block by block
		for i in xrange(0, stop - start, Mem.BLOCK_SIZE):
			if (stop - start - i) < l:
				l = stop - start - i
			err = self._caller["safe_memory_copy"](ctypes.addressof(buf), i + start, l, 0, 0, 0, pid)
			if err:
				raise Exception("Couldn't read memory")
			ret += buf.raw[:l]

		return ret

	def __setitem__(self, n, b):

		if isinstance(b, int) or isinstance(b, long):
			b = struct.pack("P", b)

		if type(b) != str:
			raise Exception("You can only set the memory to strings")

		buf = ctypes.c_buffer(b)

		if isinstance(n, int) or isinstance(n, long):
			start = n
			stop = n + len(b)
			pid = self._pid
		else:
			start = n.start
			stop = n.stop
			pid = n.step
			if not start:
				start = 0
			if not stop:
				stop = start + len(b)
			if not pid:
				pid = self._pid
			if len(b) != stop - start:
				raise "Source and Destenations are not the same length"

		# copy to memory
		err = self._caller["safe_memory_copy"](start, ctypes.addressof(buf), stop - start, 0, 0, pid, 0)
		if err:
			raise Exception("Couldn't write memory")

	def release(self):
		global KPLUGS_OBJECTS

		for i in self._allocs:
			self._caller["kfree"](i)
		self._allocs = []

		if KPLUGS_OBJECTS.count(self):
			KPLUGS_OBJECTS.remove(self)


class Hook(object):
	def __init__(self):
		global KPLUGS_OBJECTS

		self._mem = Mem()
		self._hooks = {}
		self._caller = Caller()
		KPLUGS_OBJECTS.append(self)

		# we remove the Mem object, to make sure that it will not be freed until we unhook everything
		KPLUGS_OBJECTS.remove(self._mem)

	def hook(self, where, func):
		if self._hooks.has_key(func.addr):
			raise Exception("This function is already a callback of this class")

		# create a kprobe struct
		kp = self._mem.alloc(KPROBE_STRUCT_MAXSIZE)
		if isinstance(where, str):
			sym = self._mem.alloc(len(where) + 1)
			self._mem[sym] = where + '\0'
			self._mem[kp + KPROBE_STRUCT_SYMBOL : kp + KPROBE_STRUCT_SYMBOL + WORD_SIZE] = sym
		else:
			self._mem[kp + KPROBE_STRUCT_ADDR : kp + KPROBE_STRUCT_ADDR + WORD_SIZE] = where
		self._mem[kp + KPROBE_STRUCT_HANDLER : kp + KPROBE_STRUCT_HANDLER + WORD_SIZE] = func.addr

		# register the kprobe hook
		err = self._caller["register_kprobe"](kp)
		if err:
			raise Exception("register_kprobe failed")
		self._hooks[func.addr] = kp


	def unhook(self, func):
		if isinstance(func, Function):
			addr = func.addr
		else:
			addr = func

		if not self._hooks.has_key(addr):
			raise Exception("Hook doesn't exists")
		kp = self._hooks.pop(addr)

		# unregister the kprobe hook
		self._caller["unregister_kprobe"](kp)
			


	def release(self):
		global KPLUGS_OBJECTS

		for i in self._hooks.keys():
			self.unhook(i)
		self._hooks = {}
		self._mem.release()
		if KPLUGS_OBJECTS.count(self):
			KPLUGS_OBJECTS.remove(self)

class Symbol(object):
	def __init__(self):
		global KPLUGS_OBJECTS

		self._caller = Caller()
		self._mem = Mem()
		KPLUGS_OBJECTS.append(self)

		# we remove the Mem object, to make sure that it will not be freed until we unhook everything
		KPLUGS_OBJECTS.remove(self._mem)


	def __getitem__(self, n):
		if not isinstance(n, str):
			raise Exception("Not a string")
		ret = self._caller["kallsyms_lookup_name"](n)
		if ret == 0:
			raise Exception("The symbol '%s' doesn't exists" % (n, ))
		return ret

	def release(self):
		global KPLUGS_OBJECTS

		self._mem.release()
		if KPLUGS_OBJECTS.count(self):
			KPLUGS_OBJECTS.remove(self)


