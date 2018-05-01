import socket
import ctypes
import struct
import fcntl
import array
import os

REMOTE_PORT = 6565
WORD_SIZE = struct.calcsize("P")
FREE_CACHE_SIZE = 20

class PlugWorld(object):
	ALLOC = 0
	FREE = 1
	WRITEMEM = 2
	READMEM = 3
	WRITE = 4
	READ = 5
	IOCTL = 6

	KPLUGS_IOCTYPE = 154

	_IOC_NRBITS = 8
	_IOC_TYPEBITS = 8

	_IOC_SIZEBITS = 14

	_IOC_NRSHIFT = 0
	_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
	_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
	_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS

	_IOC_WRITE = 1
	_IOC_READ = 2

	def _IOC(self, dir, type, nr, data):
		size = len(data)
		return  dir  << PlugWorld._IOC_DIRSHIFT  | \
			type << PlugWorld._IOC_TYPESHIFT | \
			nr   << PlugWorld._IOC_NRSHIFT   | \
			size << PlugWorld._IOC_SIZESHIFT

	def _IOWR(self, type, nr, data):
		return self._IOC(PlugWorld._IOC_READ | PlugWorld._IOC_WRITE, type, nr, data)

	def __init__(self, ip = None):
		self.my_objects = []
		if ip:
			self.remote = True
			self.ip = ip
			self.sock = socket.socket()
			self.sock.connect((ip, REMOTE_PORT))
			self.little_endian = struct.unpack("B", self.recvall(1))[0] != 0
			self.word_size = self.unpack("I", self.recvall(4))[0]
			self._free_cache = {}
			self._cmds = []
		else:
			self.fd = os.open('/dev/kplugs', os.O_RDWR)
			self.remote = False
			self.little_endian = struct.pack("I", 1) == struct.pack("<I", 1)
			self.word_size = WORD_SIZE

		if self.word_size == 4:
			self.form = "I"
		elif self.word_size == 8:
			self.form = "Q"
		else:
			raise Exception("Unsupported word size")
		self.mask = (2**(self.word_size*8)) - 1

	def pack(self, form, *kargs):
		if self.little_endian:
			form = "<" + form
		else:
			form = ">" + form
		return struct.pack(form, *[self.mask & i for i in kargs])

	def unpack(self, form, string):
		if self.little_endian:
			form = "<" + form
		else:
			form = ">" + form
		return struct.unpack(form, string)

	def sendall(self, data):
		self.sock.sendall(data)

	def recvall(self, size):
		ret = b''
		while len(ret) < size:
			n = self.sock.recv(size - len(ret))
			if n == '':
				raise Exception('The socket was closed')
			ret += n
		return ret

	def _flush(self):
		assert len(self._cmds)
		ret = ""
		for i in range(len(self._cmds)):
			ans = self.recvall(struct.calcsize(self.form*2))
			ret = self.recvall(self.unpack(self.form, ans[:self.word_size])[0])
			cmd = self._cmds[i]
			if cmd[1]: # critical
				res, ret = ret[:self.word_size], ret[self.word_size:]
				if self.little_endian:
					res = res[:struct.calcsize("i")]
				else:
					res = res[-struct.calcsize("i"):][::-1]
				res = self.unpack("i", res)[0]
				if res < 0:
					self._cmds = self._cmds[i + 1:]
					raise Exception("%s(%d/%d): %d" % (cmd[0], i, len(self._cmds), res))
		self._cmds = []
		return ret

	def _send_command(self, typ, data, name = "", critical = False):
		self.sendall(self.pack(self.form*2, len(data), typ))
		self.sendall(data)
		self._cmds.append([name, critical])

	def ioctl(self, op, data, complete = False):
		if self.remote:
			self._send_command(PlugWorld.IOCTL, self.pack(self.form, op) + data, "Ioctl", True)
			if complete:
				return self._flush()

		else:
			arr = array.array('B', [i for i in data])
			op = self._IOWR(PlugWorld.KPLUGS_IOCTYPE, op, data)
			fcntl.ioctl(self.fd, op, arr)
			return arr.tostring()



	def write(self, data, complete = False):
		if self.remote:
			self._send_command(PlugWorld.WRITE, data, "Write", True)
			if complete:
				self._flush()
		else:
			os.write(self.fd, data)

	def read(self, size):
		if self.remote:
			self._send_command(PlugWorld.READ, self.pack(self.form, size), "Read", True)
			return self._flush()
		else:
			return os.read(self.fd, size)

	def alloc(self, size):
		if self.remote:
			cache = [i for i in self._free_cache if self._free_cache[i] >= size]
			if len(cache):
				if len(cache) == 1:
					self._free_cache.pop(cache[0])
					return cache[0]
				m = min(*cache, key=lambda i:self._free_cache[i])
				self._free_cache.pop(m)
				return m

			self._send_command(PlugWorld.ALLOC, self.pack(self.form, size))
			ret = self.unpack(self.form, self._flush())[0]
			if not ret:
				raise Exception("Remote malloc failed")
			self.my_objects.append([ret, size])
			return ret
		else:
			obj = ctypes.c_buffer(size)
			self.my_objects.append(obj)
			return ctypes.addressof(obj)

	def free(self, addr, force=False):
		if self.remote:
			if type(addr) == list:
				obj = addr
			else:
				obj = [i for i in self.my_objects if i[0] == addr][0]

			if not force:
				if len(self._free_cache) < FREE_CACHE_SIZE:
					self._free_cache[obj[0]] = obj[1]
					return
					m = min(*self._free_cache, key=lambda i:i[1])
				else:
					if m[1] < obj[1]:
						self._free_cache[obj[0]] = obj[1]
						obj = m
			self._send_command(PlugWorld.FREE, self.pack(self.form, obj[0]))
			self.my_objects.remove(obj)
		else:
			obj = [i for i in self.my_objects if ctypes.addressof(i) == addr][0]
			self.my_objects.remove(obj)


	def close(self):
		if self.remote:
			objs = self.my_objects[:]
			for obj in objs:
				self.free(obj, True)
			self._flush()
			self.sock.close()
			self._free_cache = {}
		else:
			os.close(self.fd)
			self.fd = -1
		self.my_objects = []

	def mem_write(self, addr, data):
		if self.remote:
			data = self.pack(self.form, addr) + data
			self._send_command(PlugWorld.WRITEMEM, data)
		else:
			found = None
			for obj in self.my_objects:
				obj_addr = ctypes.addressof(obj)
				if addr >= obj_addr and (addr + len(data)) <= (obj_addr + len(obj)):
					found = obj
					break

			if found is None:
				raise Exception('Wrong address!')
			found[addr - obj_addr: (addr - obj_addr) + len(data)] = data

	def mem_read(self, addr, size):
		if self.remote:
			self._send_command(PlugWorld.READMEM, self.pack(self.form*2, size, addr))
			return self._flush()
		else:
			found = None
			for obj in self.my_objects:
				obj_addr = ctypes.addressof(obj)
				if addr >= obj_addr and (addr + size) <= (obj_addr + len(obj)):
					found = obj
					break

			if not found:
				raise Exception('Wrong address!')
			return found[addr - obj_addr: (addr - obj_addr) + size]
