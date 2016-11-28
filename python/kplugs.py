#!/usr/bin/python

from core import Plug, Function
import threading
import ctypes
import struct

# we want it to be global because we don't want hooks callbacks to be freed under our feet in case that the module was not closed correctly
KPLUGS_OBJECTS = []

KPROBE_STRUCT_MAXSIZE = 0x40
KPROBE_STRUCT_ADDR    = 5
KPROBE_STRUCT_SYMBOL  = 6
KPROBE_STRUCT_HANDLER = 8

WORD_SIZE = struct.calcsize("P")

class PlugsCache(object):
	class OneCache(object):
		def __init__(self, ip):
			self.plug = Plug(ip = ip)
			self.count = 1

	def __init__(self):
		self._ip2plug = {}
		self._plug2ip = {}
		self._lock = threading.Lock()

	def new_plug(self, ip = None):
		self._lock.acquire()
		try:
			if self._ip2plug.has_key(ip):
				self._ip2plug[ip].count += 1
				return self._ip2plug[ip].plug;
			else:
				plug = PlugsCache.OneCache(ip)
				self._ip2plug[ip] = plug
				self._plug2ip[plug.plug] = ip
				return plug.plug
		finally:
			self._lock.release()

	def release(self, plug):
		self._lock.acquire()
		try:
			ip = self._plug2ip[plug]
			self._ip2plug[ip].count -= 1
			if self._ip2plug[ip].count == 0:
				self._ip2plug.pop(ip)
				self._plug2ip.pop(plug)
				plug.close()
		finally:
			self._lock.release()

kplugs_cache = PlugsCache()

# unload kplugs - it's important unload the library or the computer may crash if you use hooks!
def release_kplugs():
	global KPLUGS_OBJECTS

	while len(KPLUGS_OBJECTS) != 0:
		KPLUGS_OBJECTS[0].release()


# a memory class
class Mem(object):
	BLOCK_SIZE = 0x1000

	def _build_mem_funcs(self):
		f = '''
ANONYMOUS('alloc')
ANONYMOUS('free')
ANONYMOUS('safe_memcpy')
ERROR_MEM = 1

def alloc(size, gfp):
	ret = KERNEL___kmalloc(size, gfp)
	if not ret:
		raise ERROR_MEM
	KERNEL_memset(ret, 0, size)
	return ret

def free(ptr):
	KERNEL_kfree(ptr)

def safe_memcpy(dst, src, size, dpid, spid):
	ret = KERNEL_safe_memory_copy(dst, src, size, 0, 0, dpid, spid)
	if ret:
		raise (-ret) & 0xfffffff
'''

		self._kmalloc, self._kfree, self._safe_memcpy = self._plug.compile(f)

	# allocate a kernel buffer
	def alloc(self, size, gfp = 0, dont_free = False):
		assert self._valid, "The object was already released!"
		ret = self._kmalloc(size, gfp)
		if not dont_free:
			self._allocs.append(ret)
		return ret

	# free a kernel buffer
	def free(self, ptr):
		assert self._valid, "The object was already released!"
		if self._allocs.count(ptr) == 0:
			raise Exception("This address don't belongs to the memory")
		if self._allocs.count(ptr):
			self._allocs.remove(ptr)
		self._kfree(ptr)

	def __init__(self, default_pid = 0, ip = None, caller = None):
		global KPLUGS_OBJECTS

		self._pid = default_pid
		self._allocs = []
		self._plug = kplugs_cache.new_plug(ip = ip)
		self.word_size = self._plug.world.word_size
		self._build_mem_funcs()

		KPLUGS_OBJECTS.append(self)
		self._valid = True

	def __getitem__(self, n):
		assert self._valid, "The object was already released!"

		buf = self._plug.world.alloc(Mem.BLOCK_SIZE)
		try:
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
				err = self._safe_memcpy(buf, i + start, l, 0, pid)
				if err:
					raise Exception("Couldn't read memory")
				ret += self._plug.world.mem_read(buf, l)

			return ret
		finally:
			self._plug.world.free(buf)

	def __setitem__(self, n, b):
		assert self._valid, "The object was already released!"

		if isinstance(b, int) or isinstance(b, long):
			b = self._plug.world.pack(self._plug.world.form, b)

		if type(b) != str:
			raise Exception("You can only set the memory to strings")

		buf = self._plug.world.alloc(len(b))
		try:
			self._plug.world.mem_write(buf, b)

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
			err = self._safe_memcpy(start, buf, stop - start, pid, 0)
			if err:
				raise Exception("Couldn't write memory")
		finally:
			self._plug.world.free(buf)

	def release(self):
		assert self._valid, "The object was already released!"
		global KPLUGS_OBJECTS

		self._valid = False
		for i in self._allocs:
			self._kfree(i)
		self._allocs = []

		if KPLUGS_OBJECTS.count(self):
			KPLUGS_OBJECTS.remove(self)
		kplugs_cache.release(self._plug)


class Caller(object):

	def _build_caller_func(self):
		f = '''
ANONYMOUS('caller')
ERROR_PARAM = 5
ERROR_NAME = 9

def caller(name, variable_argument, length, %s):
	pointer(c)
	c = KERNEL_find_external_function(name)
	if c == 0:
		raise ERROR_NAME
''' % (', '.join(['arg%d' % i for i in range(10)]), )
		first = ''
		for i in xrange(11):
			args = ', '.join(['arg%d' % j for j in range(i)])
			f += '''
	if length == %d:
		if variable_argument:
			return VARIABLE_ARGUMENT(c%s%s)
		else:
			return c(%s)
''' % (i, first,args, args)
			first = ', '
		f += '''
	else:
		raise ERROR_PARAM
'''
		self._func = self.plug.compile(f)[0]

	def __init__(self, variable_argument = False, ip = None):
		global KPLUGS_OBJECTS

		self._va = variable_argument
		self.plug = kplugs_cache.new_plug(ip = ip)
		self.word_size = self.plug.world.word_size
		self.random_names = {}
		self._build_caller_func()
		self._mem = Mem(ip = ip)
		self._args = None
		self._args_len = 0

		KPLUGS_OBJECTS.append(self)

		# we remove the Mem object, to make sure that it will not be freed until we unhook everything
		KPLUGS_OBJECTS.remove(self._mem)

		self._valid = True

	def realloc(self, new_length):
		if new_length <= self._args_len:
			return

		n = self._mem.alloc(new_length)
		if self._args:
			self._mem.free(self._args)
		self._args = n

	def __getitem__(self, n):
		assert self._valid, "The object was already released!"
		assert isinstance(n, str), Exception("Not a string")
		assert len(n) > 0, Exception("Wrong string length")

		def caller(*args):
			assert self._valid, "The object was already released!"
			assert len(args) <= 10, "To much arguments for kernel function"

			new_args = []
			buf = n + "\0"
			all_length = sum(map(lambda i:len(i) + 1, filter(lambda i:type(i) == str, args))) + len(n) + 1
			self.realloc(all_length)

			for arg in args:
				if type(arg) == str:
					new_args.append(self._args + len(buf))
					buf += arg + "\0"

				else:
					new_args.append(arg)

			self._mem[self._args:self._args + len(buf)] = buf
			new_args = list(new_args) + [0]*(10 - len(new_args))

			va = 0
			if self._va:
				va = 1
			return self._func(self._args, va, len(args), *new_args)

		return caller

	def release(self):
		global KPLUGS_OBJECTS

		assert self._valid, "The object was already released!"

		self._valid = False
		if self._args:
			self._mem.free(self._args)
		kplugs_cache.release(self.plug)
		if KPLUGS_OBJECTS.count(self):
			KPLUGS_OBJECTS.remove(self)
		self._mem.release()

class Hook(object):
	def __init__(self, ip = None):
		global KPLUGS_OBJECTS

		self._mem = Mem(ip = ip)
		self._hooks = {}
		self._caller = Caller(ip = ip)
		self.word_size = self._caller.word_size
		KPLUGS_OBJECTS.append(self)

		# we remove the Mem object, to make sure that it will not be freed until we unhook everything
		KPLUGS_OBJECTS.remove(self._mem)
		KPLUGS_OBJECTS.remove(self._caller)
		self._valid = True

	def hook(self, where, func):
		assert self._valid, "The object was already released!"
		if self._hooks.has_key(func.addr):
			raise Exception("This function is already a callback of this class")

		# create a kprobe struct
		kp = self._mem.alloc(KPROBE_STRUCT_MAXSIZE*self.word_size)
		if isinstance(where, str):
			sym = self._mem.alloc(len(where) + 1)
			self._mem[sym] = where + '\0'
			self._mem[kp + KPROBE_STRUCT_SYMBOL*self.word_size : kp + (KPROBE_STRUCT_SYMBOL + 1)*self.word_size] = sym
		else:
			self._mem[kp + KPROBE_STRUCT_ADDR*self.word_size : kp + (KPROBE_STRUCT_ADDR + 1)*self.word_size] = where
		self._mem[kp + KPROBE_STRUCT_HANDLER*self.word_size : kp + (KPROBE_STRUCT_HANDLER + 1)*self.word_size] = func.addr

		# register the kprobe hook
		err = self._caller["register_kprobe"](kp)
		if err:
			raise Exception("register_kprobe failed")
		self._hooks[func.addr] = kp


	def unhook(self, func):
		assert self._valid, "The object was already released!"
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
		assert self._valid, "The object was already released!"
		global KPLUGS_OBJECTS

		self._valid = False
		for i in self._hooks.keys():
			self.unhook(i)
		self._hooks = {}
		self._mem.release()
		if KPLUGS_OBJECTS.count(self):
			KPLUGS_OBJECTS.remove(self)
		self._caller.release()

class Symbol(object):
	def __init__(self, ip = None):
		global KPLUGS_OBJECTS

		self._caller = Caller(ip = ip)
		self._mem = Mem(ip = ip)
		assert self._caller.word_size == self._mem.word_size, "Inconsistant word size!"
		self.word_size = self._caller.word_size

		KPLUGS_OBJECTS.append(self)

		# we remove the Mem object, to make sure that it will not be freed until we unhook everything
		KPLUGS_OBJECTS.remove(self._mem)
		KPLUGS_OBJECTS.remove(self._caller)
		self._valid = True


	def __getitem__(self, n):
		assert self._valid, "The object was already released!"
		if not isinstance(n, str):
			raise Exception("Not a string")
		ret = self._caller["kallsyms_lookup_name"](n)
		if ret == 0:
			ret = self._caller["find_symbol"](n, 0, 0, 1, 0)
			if ret == 0:
				raise Exception("The symbol '%s' doesn't exists" % (n, ))
			else:
				return struct.unpack(self._caller.plug.world.form, self._mem[ret:ret+self.word_size])[0]
		return ret

	def release(self):
		assert self._valid, "The object was already released!"
		global KPLUGS_OBJECTS

		self._valid = False
		self._mem.release()
		if KPLUGS_OBJECTS.count(self):
			KPLUGS_OBJECTS.remove(self)
		self._caller.release()
