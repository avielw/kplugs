#!/usr/bin/python

from .core import PlugCore, Function
import traceback
import threading
import ctypes
import struct

KPROBE_STRUCT_MAXSIZE = 0x40
KPROBE_STRUCT_ADDR    = 5
KPROBE_STRUCT_SYMBOL  = 6
KPROBE_STRUCT_HANDLER = 8

WORD_SIZE = struct.calcsize("P")

class Plug(PlugCore):
	def __init__(self, glob = False, ip = None):
		self.cache = None
		self.ctx = None
		super(Plug, self).__init__(glob, ip)

	def close(self, keep_globals=False):

		if self.cache:
			self.cache.release(self)
			return

		super(Plug, self).close(keep_globals)

class ObjCache(object):
	class OneCache(object):
		def __init__(self, args, ctx, obj):
			if not obj is Plug:
				args = (ctx,) + args
			self.obj = obj(*args)
			self.count = 1

	def __init__(self, ctx, obj):
		self._args2obj = {}
		self._obj2args = {}
		self._lock = threading.Lock()
		self._obj = obj
		self._ctx = ctx

	def new_obj(self, args = ()):

		self._lock.acquire()
		try:
			if args in self._args2obj:
				self._args2obj[args].count += 1
				return self._args2obj[args].obj;
			else:
				obj = ObjCache.OneCache(args, self._ctx, self._obj)
				self._args2obj[args] = obj
				self._obj2args[obj.obj] = args
				obj.obj.cache = self
				return obj.obj
		finally:
			self._lock.release()

	def releaseall_and_warn(self):
		self._lock.acquire()
		try:
			while len(self._args2obj):
				print("Warning: an orphan object was released")
				o = self._args2obj[self._args2obj.keys()[0]]
				o.count = 1
				try:
					self.release(o, False)
				finally:
					print(traceback.format_exc())
		finally:
			self._lock.release()

	def release(self, obj, lock=True):
		release = False
		if lock:
			self._lock.acquire()
		try:
			args = self._obj2args[obj]
			self._args2obj[args].count -= 1
			if self._args2obj[args].count == 0:
				self._args2obj.pop(args)
				self._obj2args.pop(obj)
				obj.cache = None
				release = True
		finally:
			if lock:
				self._lock.release()
		if release:
			obj.close()


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

	def __init__(self, context, default_pid = 0, ip = None):
		self.cache = None
		self.ctx = context
		self._pid = default_pid
		self._allocs = []
		self._plug = self.ctx.cache["Plug"].new_obj((False, ip))
		self.word_size = self._plug.world.word_size
		self._build_mem_funcs()

		self._valid = True

	def __getitem__(self, n):
		assert self._valid, "The object was already released!"

		buf = self._plug.world.alloc(Mem.BLOCK_SIZE)
		try:
			if isinstance(n, int) or isinstance(n, int):
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

			ret = b""
			l = Mem.BLOCK_SIZE

			# copy the from memory block by block
			for i in range(0, stop - start, Mem.BLOCK_SIZE):
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

		if isinstance(b, int) or isinstance(b, int):
			b = self._plug.world.pack(self._plug.world.form, b)

		if type(b) is str:
			b = b.encode()

		if type(b) != bytes:
			raise Exception("You can only set the memory to bytes")

		buf = self._plug.world.alloc(len(b))
		try:
			self._plug.world.mem_write(buf, b)

			if isinstance(n, int) or isinstance(n, int):
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

	def close(self):
		assert self._valid, "The object was already released!"

		if self.cache:
			self.cache.release(self)
			return

		self._valid = False
		for i in self._allocs:
			self._kfree(i)
		self._allocs = []

		self._plug.close()


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
		for i in range(11):
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

	def __init__(self, context, variable_argument = False, ip = None):
		self.cache = None
		self._va = variable_argument
		self.ctx = context
		self.plug = self.ctx.cache["Plug"].new_obj((False, ip))
		self.word_size = self.plug.world.word_size
		self.random_names = {}
		self._build_caller_func()
		self._mem = self.ctx.cache["Mem"].new_obj((0, ip))
		self._args = None
		self._args_len = 0

		self._valid = True

	def realloc(self, new_length):
		if new_length <= self._args_len:
			return

		n = self._mem.alloc(new_length)
		if self._args:
			self._mem.free(self._args)
		self._args = n
		self._args_len = new_length

	def __getitem__(self, n):
		assert self._valid, "The object was already released!"
		assert isinstance(n, str), Exception("Not a string")
		assert len(n) > 0, Exception("Wrong string length")

		if type(n) is str:
			n = n.encode()

		def caller(*args):
			assert self._valid, "The object was already released!"
			assert len(args) <= 10, "To much arguments for kernel function"

			new_args = []
			buf = n + b"\0"
			all_length = sum([len(i) + 1 for i in [i for i in args if type(i) == str]]) + len(n) + 1
			self.realloc(all_length)

			for arg in args:
				if type(arg) is str:
					arg = arg.encode()

				if type(arg) is bytes:
					new_args.append(self._args + len(buf))
					buf += arg + b"\0"

				else:
					new_args.append(arg)

			self._mem[self._args:self._args + len(buf)] = buf
			new_args = list(new_args) + [0]*(10 - len(new_args))

			va = 0
			if self._va:
				va = 1
			return self._func(self._args, va, len(args), *new_args)

		return caller

	def close(self):
		assert self._valid, "The object was already released!"

		if self.cache:
			self.cache.release(self)
			return

		self._valid = False
		if self._args:
			self._mem.free(self._args)
		self.plug.close()
		self._mem.close()

class Hook(object):
	def __init__(self, context, ip = None):
		self.cache = None
		self.ctx = context
		self._mem = self.ctx.cache["Mem"].new_obj((0, ip))
		self._hooks = {}
		self._caller = self.ctx.cache["Caller"].new_obj((False, ip))
		self.word_size = self._caller.word_size

		self._valid = True

	def hook(self, where, func):
		assert self._valid, "The object was already released!"
		if func.addr in self._hooks:
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

		if addr not in self._hooks:
			raise Exception("Hook doesn't exists")
		kp = self._hooks.pop(addr)

		# unregister the kprobe hook
		self._caller["unregister_kprobe"](kp)



	def close(self):
		assert self._valid, "The object was already released!"

		if self.cache:
			self.cache.release(self)
			return

		self._valid = False
		for i in list(self._hooks.keys()):
			self.unhook(i)
		self._hooks = {}
		self._mem.close()
		self._caller.close()

class Symbol(object):
	def __init__(self, context, ip = None):
		self.cache = None
		self.ctx = context
		self._caller = self.ctx.cache["Caller"].new_obj((False, ip))
		self._mem = self.ctx.cache["Mem"].new_obj((0, ip))
		assert self._caller.word_size == self._mem.word_size, "Inconsistant word size!"
		self.word_size = self._caller.word_size

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

	def close(self):
		assert self._valid, "The object was already released!"

		if self.cache:
			self.cache.release(self)
			return

		self._valid = False
		self._mem.close()
		self._caller.close()

class Context(object):
	def __init__(self, ip=None):
		self._valid = True

		self._lock = threading.Lock()

		self.objs  = []
		self.cache = {
			'Plug'   : ObjCache(self, Plug),
			'Mem'    : ObjCache(self, Mem),
			'Hook'   : ObjCache(self, Hook),
			'Symbol' : ObjCache(self, Symbol),
			'Caller' : ObjCache(self, Caller),
}

	def append(self, obj):
		class KplugsObjectWrapper(object):
			def __init__(self, ctx, obj):
				self._wrapper_valid = True
				self.obj = obj
				self.ctx = ctx

			def __repr__(self):
				return repr(self.obj)

			def __getattr__(self, attr):
				if attr in self.__dict__:
					return getattr(self, attr)
				return getattr(self.obj, attr)

			def __getitem__(self, n):
				return self.obj.__getitem__(n)

			def __setitem__(self, n, b):
				return self.obj.__setitem__(n, b)

			def close(self):
				assert self._wrapper_valid, "The object was already released!"
				self.ctx.remove(self)
				self._wrapper_valid = False
				self.obj.close()

		self._lock.acquire()
		try:
			assert not self.objs.count(obj), "The object is already attached to this context!"
			obj = KplugsObjectWrapper(self, obj)
			self.objs.append(obj)
			return obj
		finally:
			self._lock.release()

	def remove(self, obj):
		self._lock.acquire()
		try:
			if self.objs.count(obj):
				self.objs.remove(obj)
		finally:
			self._lock.release()

	def Plug(self, glob = False, ip = None):
		assert self._valid, "The object was already released!"

		plug = self.cache["Plug"].new_obj((glob, ip))
		assert plug.ctx is None or plug.ctx is self, "An invalid Plug was created!"
		plug.ctx = self
		return self.append(plug)


	def Mem(self, default_pid = 0, ip = None):
		assert self._valid, "The object was already released!"
		return self.append(self.cache["Mem"].new_obj((default_pid, ip)))

	def Caller(self, variable_argument = False, ip = None):
		assert self._valid, "The object was already released!"
		return self.append(self.cache["Caller"].new_obj((variable_argument, ip)))

	def Symbol(self, ip = None):
		assert self._valid, "The object was already released!"
		return self.append(self.cache["Symbol"].new_obj((ip,)))

	def Hook(self, ip = None):
		assert self._valid, "The object was already released!"
		return self.append(self.cache["Hook"].new_obj((ip,)))

	def __enter__(self):
		return self

	def __exit__(self, type, value, tb):
		self.close()

	def close(self):
		assert self._valid, "The object was already released!"
		while len(self.objs):
			try:
				o = self.objs[0]
				o.close()
			except Exception:
				print(traceback.format_exc())

		for i in ("Plug", "Mem", "Caller", "Symbol", "Hook"):
			self.cache[i].releaseall_and_warn()

		self._valid = False
