#!/usr/bin/python

import ast
from _ast import *
from . import world
import struct
import ctypes
import os

WORD_SIZE = struct.calcsize("P")
VERSION   = (3, 3)

# the kplugs main class
class PlugCore(object):

	# kplugs commands:
	KPLUGS_REPLY = 0
	KPLUGS_LOAD = 1
	KPLUGS_EXECUTE = 2
	KPLUGS_EXECUTE_ANONYMOUS = 3
	KPLUGS_UNLOAD = 4
	KPLUGS_UNLOAD_ANONYMOUS = 5
	KPLUGS_SEND_DATA = 6
	KPLUGS_SEND_DATA_ANONYMOUS = 7
	KPLUGS_RECV_DATA = 8
	KPLUGS_RECV_DATA_ANONYMOUS = 9

	ERROR_TABLE = [
	"",
	"No more memory",
	"Recursion to deep",
	"Wrong operation",
	"Wrong variable",
	"Wrong parameter",
	"This operation is been used more the once",
	"A flow block was not terminated",
	"Some of the code was not explored",
	"Bad function name",
	"Function already exists",
	"The stack is empty",
	"Bad pointer",
	"Access outside of a buffer's limit",
	"Divide by zero",
	"Unknown function",
	"Bad number of arguments",
	"Wrong architecture",
	"Unsupported version",
	"Not a dynamic memory",
	"Operation was interrupted",
	"Could not block",
	]


	def __init__(self, glob = False, ip = None):
		self.world = world.PlugWorld(ip)
		self.word_size = self.world.word_size
		self.funcs = []
		self.glob = glob
		self.last_exception = []

	def _exec_cmd(self, op, len1, len2, val1, val2, nonblock=False):
		ws = self.word_size
		word_size  = self.word_size
		word_size |= (1 << 6) # supports only little endian version.
		if self.glob:
			word_size |= (1 << 7)
		if nonblock:
			word_size |= (1 << 5)

		header = bytes([word_size, VERSION[0], VERSION[1], 0])
		header = (header + b"\0"*ws)[:ws]
		data   = header + self.world.pack(self.world.form*4, len1, len2, val1, val2)
		excep  = struct.pack(self.world.form*4, 0, 0, 0, 0)
		ret    = self.world.ioctl(op, data + excep, True)
		data   = ret[:len(data)]
		excep  = ret[len(data):]
		error  = data[3] or excep[0]
		if error:
			if excep[0]:
				_, exc, func, pc = struct.unpack(self.world.form*4, excep)
				self.last_exception = [func, pc]
			else:
				exc = data[3]
			if exc >= len(PlugCore.ERROR_TABLE):
				raise Exception("Error: 0x%x" % exc)
			raise Exception(PlugCore.ERROR_TABLE[exc])

		_, _, val1, _ = struct.unpack(self.world.form*4, data[ws:])
		return val1

	def load(self, func, unhandled_return = None, function_type = 0):
		op = PlugCore.KPLUGS_LOAD
		if not type(func) is list:
			func = [func]

		offsets = []
		data = b""
		for f in func:
			offsets.append(len(data))
			data += f.to_bytes(unhandled_return, function_type, self.world)

		buf = self.world.alloc(len(data))
		try:
			self.world.mem_write(buf, data)

			offsets.append(len(data))
			for i in range(len(offsets) - 1):
				# send the command (will throw an exception if it fails)
				func[i].addr = self._exec_cmd(op, offsets[i + 1] - offsets[i], 0, buf + offsets[i], 0)
				func[i].plug = self
				self.funcs.append(func[i])
		finally:
			self.world.free(buf)


	def compile(self, code, unhandled_return = None, function_type = 0):
		# create a visitor and compile
		visitor = compiler_visitor(self)
		p = ast.parse(code)
		visitor.visit(p)

		# load all the functions
		self.load(visitor.functions, unhandled_return, function_type)

		return [i for i in visitor.functions if not i.static]

	def unload(self, func):
		for f in list(func.special_funcs.keys()):
			func.special_funcs[f].unload()

		func.special_funcs = {}

		if func.anonymous:
			op = PlugCore.KPLUGS_UNLOAD_ANONYMOUS
			length = 0
			ptr = func.addr
			name_buf = 0
		else:
			op = PlugCore.KPLUGS_UNLOAD
			length = len(func.name)
			name_buf = self.world.alloc(len(func.name))
			self.world.mem_write(name_buf, func.name)
			ptr = name_buf

		try:
			# send the command (will throw an exception if it fails)
			self._exec_cmd(op, length, 0, ptr, 0)
			self.funcs.remove(func)
		finally:
			if name_buf:
				self.world.free(name_buf)


	def send(self, func, data, nonblock=False):
		if type(data) is str:
			data = data.encode()

		if func.anonymous:
			op = PlugCore.KPLUGS_SEND_DATA_ANONYMOUS
			length = 0
			ptr = func.addr
			name_buf = 0
		else:
			op = PlugCore.KPLUGS_SEND_DATA
			length = len(func.name)
			name_buf = self.world.alloc(len(func.name))
			self.world.mem_write(name_buf, func.name)
			ptr = name_buf

		try:
			addr = self.world.alloc(len(data))
			try:
				self.world.mem_write(addr, data)
				return self._exec_cmd(op, length, len(data), ptr, addr, nonblock)
			finally:
				self.world.free(addr)
		finally:
			if name_buf:
				self.world.free(name_buf)

	def recv(self, func, buf_length, nonblock=False):
		addr = 0
		try:
			if func.anonymous:
				op = PlugCore.KPLUGS_RECV_DATA_ANONYMOUS
				length = 0
				ptr = func.addr
				addr = self.world.alloc(buf_length)
			else:
				op = PlugCore.KPLUGS_RECV_DATA
				length = len(func.name)
				addr = self.world.alloc(buf_length + len(func.name))
				ptr = addr + buf_length
				self.world.mem_write(ptr, func.name)

			real_length = self._exec_cmd(op, length, buf_length, ptr, addr, nonblock)
			return self.world.mem_read(addr, min(buf_length, real_length))
		finally:
			if addr:
				self.world.free(addr)

	def __call__(self, func, *args):
		if not func in self.funcs:
			raise Exception("This function doesn't belongs to this plug")

		allocs = []
		data = b""
		ws = self.word_size
		if func.anonymous:
			op = PlugCore.KPLUGS_EXECUTE_ANONYMOUS
			length = 0
			ptr = func.addr
			name_buf = 0
		else:
			op = PlugCore.KPLUGS_EXECUTE
			length = len(func.name)
			allocs.append(len(data))
			data += func.name
			data += b"\0" * (ws - (len(data) % ws))


		new_args = []
		addr = 0
		try:
			read_back = False
			for arg in args:
				if isinstance(arg, str):
					arg = arg.encode()

				if isinstance(arg, bytes):
					allocs.append(len(data))
					data += arg
					data += b"\0" * (ws - (len(data) % ws))
				elif isinstance(arg, bytearray):
					read_back = True
					allocs.append(len(data))
					data += bytes(arg)
					data += b"\0" * (ws - (len(data) % ws))
				else:
					allocs.append(0)

			addr = self.world.alloc(len(data) + len(args)*ws)
			args_buf = addr + len(data)
			if not func.anonymous:
				ptr = addr
				allocs = allocs[1:]

			for i in range(len(args)):
				if isinstance(args[i], str) or isinstance(args[i], bytes) or isinstance(args[i], bytearray):
					arg = addr + allocs[i]
				else:
					arg = args[i]
				new_args.append(arg)

			local_buf = self.world.pack(self.world.form * len(new_args), *new_args)
			self.world.mem_write(addr, data + local_buf)

			# send the command (will throw an exception if it fails)
			try:
				return self._exec_cmd(op, length, len(args) * ws, ptr, args_buf)
			finally:
				if read_back:
					data = self.world.mem_read(addr, len(data))
					for i in range(len(args)):
						if isinstance(args[i], bytearray):
							args[i][:len(args[i])] = data[allocs[i]:allocs[i] + len(args[i])]
		finally:
			if addr:
				self.world.free(addr)

	# you MUST call this member if the plug is global or the functions will never be freed!
	def close(self, keep_globals=False):
		if self.glob and keep_globals:
			while len(self.funcs) != 0:
				self.unload(self.funcs[0])

		# we don't need to unload functions if it's not global because closing the file will do it for us
		self.funcs = []
		self.world.close()




RESERVED_PREFIX =	["KERNEL"]
RESERVED_NAMES = 	["VARIABLE_ARGUMENT", "ANONYMOUS", "STATIC", "ADDRESSOF", "word", "buffer", "array", "pointer", "new", "delete", "recv", "send"]
RESERVED_FUNCTIONS = 	["_"]

# validate name
def validate_name(name):
	for pre in RESERVED_PREFIX:
		if name.startswith(pre):
			raise Exception("Illegal function name: '%s'" % (name, ))
	if name in RESERVED_NAMES or name in RESERVED_FUNCTIONS:
		raise Exception("Illegal function name: '%s'" % (name, ))

# a Function class
# you should not use it directly but through the Plug class
class Function(object):

	# Parameters:
	PARAM_GLOBAL = 1
	PARAM_NONBLOCK = 2

	# Operations:
	OP_FUNCTION = 0
	OP_VARIABLE = 1
	OP_FLOW = 2
	OP_EXPRESSION = 3

	# Vars:
	VAR_UNDEF = -1
	VAR_WORD = 0
	VAR_BUF = 1
	VAR_ARRAY = 2
	VAR_POINTER = 3

	# Flow:
	FLOW_ASSIGN = 0
	FLOW_ASSIGN_OFFSET = 1
	FLOW_IF = 2
	FLOW_TRY = 3
	FLOW_WHILE = 4
	FLOW_DYN_FREE = 5
	FLOW_SEND_DATA = 6

	FLOW_BLOCKEND = 7
	FLOW_THROW = 8
	FLOW_RET = 9

	# Expressions:
	EXP_WORD = 0
	EXP_VAR = 1
	EXP_STRING = 2
	EXP_EXCEPTION_VAR = 3

	EXP_ADDRESSOF = 4
	EXP_DEREF = 5

	EXP_BUF_OFFSET = 6
	EXP_ADD = 7
	EXP_SUB = 8
	EXP_MUL_UNSIGN = 9
	EXP_MUL_SIGN = 10
	EXP_DIV_UNSIGN = 11
	EXP_DIV_SIGN = 12
	EXP_AND = 13
	EXP_XOR = 14
	EXP_OR = 15
	EXP_BOOL_AND = 16
	EXP_BOOL_OR = 17
	EXP_NOT = 18
	EXP_BOOL_NOT = 19
	EXP_MOD = 20
	EXP_CALL_STRING = 21
	EXP_CALL_PTR = 22
	EXP_CALL_END = 23
	EXP_CMP_EQ = 24
	EXP_CMP_UNSIGN = 25
	EXP_CMP_SIGN = 26
	EXP_EXT_SIGN = 27
	EXP_DYN_ALLOC = 28
	EXP_RECV_DATA = 29
	EXP_ARGS = 30
	EXP_EXP = 31

	FUNC_VARIABLE_ARGUMENT = 1
	FUNC_EXTERNAL = 2

	# expression operation types:

	BINOP =		{
				Add : EXP_ADD,
				Sub : EXP_SUB,
				Mult : EXP_MUL_SIGN,
				Div : EXP_DIV_SIGN,
				BitAnd : EXP_AND,
				BitXor : EXP_XOR,
				BitOr : EXP_OR,
				Mod : EXP_MOD,
			}

	UNARYOP =	{
				Not: EXP_BOOL_NOT,
				Invert: EXP_NOT,
			}

	BOOLOP =	{
				Or: EXP_BOOL_OR,
				And: EXP_BOOL_AND,
			}


	# variable types:
	VARNAMES = 	{
				"word": VAR_WORD,
				"pointer": VAR_POINTER,
				"buffer": VAR_BUF,
				"array": VAR_ARRAY,
			}


	def __init__(self, name, word_size = WORD_SIZE):
		validate_name(name)
		self.name = name.encode()
		self.word_size = word_size
		self.new_var = 1
		self.all_vars = {}
		self.vars = [] # the order is importand here
		self.args = [] # the order is importand here
		self.string_table = [] # the order is importand here
		self.anonymous = False
		self.static = False
		self.special_funcs = {}

	# get a function type opcode
	def _get_func(self, 	args,
				name,
				return_exception_value = 0,
				error_return = 0,
				function_type = 0):
		return {	"op" : Function.OP_FUNCTION,
				"min_args" : self.min_args,
				"return_exception_value" : return_exception_value,
				"name" : name,
				"error_return" : error_return,
				"function_type" : function_type }

	# get a variable type opcode
	def _get_var(self, typ, is_arg = 0, size = None, init = 0, flags = 0):
		if size is None:
			size = self.word_size
		if typ == Function.VAR_UNDEF:
			typ = Function.VAR_WORD
		return {	"op" : Function.OP_VARIABLE,
				"type" : typ,
				"is_arg" : is_arg,
				"size" : size,
				"init" : init,
				"flags" : flags }

	# get a flow type opcode
	def _get_flow(self, typ, val1 = 0, val2 = 0, val3 = 0):
		return {	"op" : Function.OP_FLOW,
				"type" : typ,
				"val1" : val1,
				"val2" : val2,
				"val3" : val3 }

	# get an expression type opcode
	def _get_exp(self, typ, val1 = 0, val2 = 0, force = False):
		if typ == Function.EXP_VAR:
			val1 = self._get_var_id(val1)
			if val1["type"] == Function.VAR_ARRAY or val1["type"] == Function.VAR_BUF:
				return self._get_exp(Function.EXP_ADDRESSOF, val1["id"])
			val1 = val1["id"]
			if not force:
				return val1
		return {	"op" : Function.OP_EXPRESSION,
				"type" : typ,
				"val1" : val1,
				"val2" : val2 }

	# get the id of a variable
	def _get_var_id(self, var_name, size = None, create = False, typ = VAR_WORD, init = 0, flags = 0):
		if size is None:
			size = self.word_size
		if var_name not in self.all_vars:
			if not create:
				# the variable dosen't exists!
				raise Exception("Variable '%s' used before assignment" % (var_name, ))
			if var_name in RESERVED_NAMES:
				raise Exception("Illegal variable name: '%s'" % (var_name, ))
			self.vars.append(var_name)
			self.all_vars[var_name] = {"id":self.new_var, "type":typ, "size":size, "init":init, "flags":flags}
			self.new_var += 1
		ret = self.all_vars[var_name]
		if ret["type"] == Function.VAR_UNDEF:
			self.all_vars[var_name] = {"id":self.all_vars[var_name]["id"], "type":typ, "size":size, "init":init, "flags":flags}
		return self.all_vars[var_name]

	# arrange the blocks and set offsets values where it is needed
	def _order_blocks(self, block):
		this_block = []
		self.all_blocks.append(this_block)

		if type(block) == dict:
			# this is an expression bloc
			self.end += 1
			to_add = {}
			for i in list(block.keys()):
				j = block[i]
				if type(block[i]) == list or type(block[i]) == dict:
					j = self.end # this block will be located in offset self.end
					self._order_blocks(block[i])
				to_add[i] = j
			this_block.append(to_add)

		elif type(block) == list:
			# this is a flow block
			self.end += len(block)
			for cmd in block:
				to_add = {}
				for i in list(cmd.keys()):
					j = cmd[i]
					if type(cmd[i]) == list or type(cmd[i]) == dict:
						j = self.end # this block will be located in offset self.end
						self._order_blocks(cmd[i])
					to_add[i] = j
				this_block.append(to_add)
		else:
			# we should never get here!
			raise Exception("order_blocks unexpected behavior")

	# translate the arranged blocks to bytes
	def _translate(self, world):
		ret = b""
		for block in self.all_blocks:
			if block["op"] == Function.OP_FUNCTION:
				ret += world.pack(world.form*4,	block["op"] | (block["min_args"] << 2) | (block["return_exception_value"] << 7),
								block["name"],
								block["error_return"],
								block["function_type"])
			elif block["op"] == Function.OP_VARIABLE:
				ret += world.pack(world.form*4,	block["op"] | (block["type"] << 2) | (block["is_arg"] << 7),
								block["size"],
								block["init"],
								block["flags"])
			elif block["op"] == Function.OP_FLOW:
				ret += world.pack(world.form*4,	block["op"] | (block["type"] << 2),
								block["val1"],
								block["val2"],
								block["val3"])

			elif block["op"] == Function.OP_EXPRESSION:
				ret += world.pack(world.form*4,	block["op"] | (block["type"] << 2),
								block["val1"],
								block["val2"],
								0)
			else:
				# we should never get here!
				raise Exception("Unknown block type")
		return ret

	# generate the string table
	def _generate_string_table(self):
		return b'\0'.join(self.string_table) + b'\0'

	# return the index of a string
	def _get_string_value(self, string):
		if type(string) is str:
			string = string.encode()

		if string[:-1].count(b'\0') != 0:
			raise Exception("Strings could not have nulls inside")
		if len(string) > 0 and string[-1] == b'\0':
			string = string[:-1]

		if self.string_table.count(string) == 0:
			self.string_table.append(string)
		return self.string_table.index(string) + 1


	# generate bytes from a compiled function
	def to_bytes(self, unhandled_return, function_type, world):
		# if unahdnled_return stays None the default return value (if an exception occured) will be the exception value

		if unhandled_return == None:
			ret_exc = 1
			ret_value = 0
		else:
			ret_exc = 0
			ret_value = unhandled_return

		name = 0

		# anonymous functions has no name
		if not self.anonymous:
			name = self._get_string_value(self.name)

		# add the function opcode and the variables opcodes
		self.all_blocks = [[self._get_func(len(self.args), name, ret_exc, ret_value, self.function_type | function_type)]]
		for i in range(len(self.all_vars)):
			if i < self.max_args:
				is_arg = 1
				typ = self.all_vars[self.args[i]]["type"]
				size = self.all_vars[self.args[i]]["size"]
				init = self.all_vars[self.args[i]]["init"]
				flags = self.all_vars[self.args[i]]["flags"]
			else:
				is_arg = 0
				typ = self.all_vars[self.vars[i - len(self.args)]]["type"]
				size = self.all_vars[self.vars[i - len(self.args)]]["size"]
				init = self.all_vars[self.vars[i - len(self.args)]]["init"]
				flags = self.all_vars[self.vars[i - len(self.args)]]["flags"]
			self.all_blocks.append([self._get_var(typ, is_arg = is_arg, size = size, init = init, flags = flags)])

		# arrange the blocks in the right order
		self.end = len(self.all_blocks)
		self._order_blocks(self.final)

		# flatten everything
		all_blocks = []
		for block in self.all_blocks:
			all_blocks += block
		self.all_blocks = all_blocks

		# return the bytes
		return self._translate(world) + self._generate_string_table()

	def unload(self):
		self.plug.unload(self)

	def send(self, data, nonblock=False):
		return self.plug.send(self, data, nonblock)

	def recv(self, length, nonblock=False):
		return self.plug.recv(self, length, nonblock)

	def __call__(self, *args):
		return self.plug(self, *args)


# the ast visitor class
# create the compiled function(s) class(es)
class compiler_visitor(ast.NodeVisitor):

	def __init__(self, plug):
		ast.NodeVisitor.__init__(self)
		self.word_size = plug.word_size
		self.in_function = False
		self.functions = []
		self.func = None
		self.block_stoped = False
		self.cur_frame = []
		self.variable_argument_funcs = []
		self.anonymous_funcs = []
		self.static_funcs = []
		self.consts = {}
		self._last_temp_var = 0
		self.plug = plug

	# add a flow opcode in the current frame
	def _create_flow(self, typ, val1 = 0, val2 = 0, val3 = 0):
		self.cur_frame[-1].append(self.func._get_flow(typ, val1, val2, val3))

	# start a new flow frame
	def _flow_new(self):
		self.cur_frame.append([])

	# return from this flow frame
	def _flow_ret(self, last = False):
		frame = self.cur_frame[-1]
		if not self.block_stoped:
			if last:
				self._create_flow(Function.FLOW_RET, self.func._get_exp(Function.EXP_WORD, 0))
			else:
				# the frame has ended without any ending block, so we should end it
				self._create_flow(Function.FLOW_BLOCKEND)

		self.block_stoped = False
		self.cur_frame = self.cur_frame[:-1]
		return frame


	# parse a call to a builtin "function" (a.k.a - the definition of a variable)
	def _parse_builtin_call(self, node, is_expr = False):
		mult = 1
		flags = 0
		values = []
		is_first = True
		for arg in node.args:
			if is_expr and is_first:
				# ignoring the first argument
				is_first = False
				continue
			if type(arg) == Num:
				values.append(arg.n)
			elif type(arg) == Name and arg.id in self.consts:
				values.append(self.consts[arg.id])
			else:
				raise Exception("Invalid assign")

		if node.func.id == "array":
			mult = self.word_size
		if node.func.id == "word" or node.func.id == "pointer":
			size = self.word_size
			init = 0
			if len(node.args) > 1:
				raise Exception("Invalid assign")

			if len(values) >= 1:
				init = values[0]
		else:
			if len(values) == 0 or len(values) > 2:
				raise Exception("Invalid assign")
			size = values[0]
			init = 0
			if len(values) >= 2:
				init = values[0]
		return Function.VARNAMES[node.func.id], size * mult, init, flags

	# parse one assignment (meaning - one target and one value)
	def _one_assign(self, target, value, value_explored = False):

		if type(value) == Call:
			# check if this is a variable definition assignment
			if type(value.func) == Name and value.func.id in list(Function.VARNAMES.keys()):
				if target.id in self.func.all_vars:
					raise Exception("Variable '%s' already exists" % (target.id, ))

				typ, size, init, flags = self._parse_builtin_call(value)

				if target.id in self.consts:
					raise Exception("Assigning to a constant")

				self.func._get_var_id(target.id, size = size, create = True, typ = typ, init = init, flags = flags)
				return

		var = None

		if not value_explored:
			value = self.visit(value)
		if type(target) == Name:
			# the target is a variable
			if target.id in self.consts:
				raise Exception("Assigning to a constant")

			if target.id in self.func.all_vars:
				var = self.func.all_vars[target.id]
			if var and (var["type"] == Function.VAR_BUF or var["type"] == Function.VAR_ARRAY):
				raise Exception("Cannot assign to a buffer or an array")

			# if the variable dosen't exist, it will be defined as a word
			self._create_flow(	Function.FLOW_ASSIGN,
						self.func._get_var_id(target.id, create = True)["id"],
						value)

		elif type(target) == Subscript:
			# the target may be an offset assignment

			if type(target.value) != Name or type(target.slice) != Index:
				raise Exception("Unsupported assign type")

			if target.value.id not in self.func.all_vars:
				raise Exception("Variable '%s' used before assignment" % (target.value.id, ))

			var = self.func.all_vars[target.value.id]
			if var and (var["type"] == Function.VAR_WORD):
				raise Exception("Variable '%s' cannot be used as a pointer" % (target.value.id, ))

			# handle assignments of characters
			if (var["type"] == Function.VAR_BUF or var["type"] == Function.VAR_POINTER) and isinstance(value, dict) and value["op"] == Function.OP_EXPRESSION and value["type"] == Function.EXP_STRING:
				value = self.func._get_exp(Function.EXP_DEREF, value, 1)

			self._create_flow(	Function.FLOW_ASSIGN_OFFSET,
						var["id"],
						self.visit(target.slice.value),
						value)
		elif isinstance(target, str):
			# should happen only with a temporary variable so it can't be a constant
			self._create_flow(	Function.FLOW_ASSIGN,
						self.func._get_var_id(target, create = True)["id"],
						value)

		else:
			raise Exception("Unsupported assign type")

	# create a temporary variable - the name of the variable is not a python valid name, so there can be no conflicts
	def _get_temp_var(self):
		ret = '.tempvar%d' % (self._last_temp_var, )
		self._last_temp_var += 1
		return ret

	def _create_fstring_function(self, num_args):
		if "fstring%d" % num_args in self.func.special_funcs:
			return self.func.special_funcs["fstring%d" % num_args]
		args = ', '.join(["arg%d" % (i, ) for i in range(num_args)])
		ret = self.plug.compile(r'''
VARIABLE_ARGUMENT("KERNEL_snprintf")

ANONYMOUS("fstring_function")
ERROR_PARAM = 5

def fstring_function(%s):
	length = KERNEL_snprintf(0, 0, %s)
	buf = new(length + 1)
	if KERNEL_snprintf(buf, length + 1, %s) != length:
		raise ERROR_PARAM
	return buf
''' % (args, args, args))[0]
		self.func.special_funcs["fstring%d" % num_args] = ret
		return ret


	# this is the callback that will be called if the script has an unknown node type
	def generic_visit(self, node):
		raise Exception("Unknown type: %s" % str(type(node)))

	def visit_Module(self, node):
		for obj in node.body:
			self.visit(obj)

	def visit_FunctionDef(self, node):
		if self.in_function:
			# you can't create a function inside a function
			raise Exception("Defining a function inside a function")

		self.func = Function(node.name, self.word_size)
		self.functions.append(self.func)
		self.in_function = True

		# set flags
		self.func.function_type = 0
		if node.name in self.variable_argument_funcs:
			self.func.function_type |= Function.FUNC_VARIABLE_ARGUMENT
		if node.name in self.anonymous_funcs:
			self.func.anonymous = True
		if node.name in self.static_funcs:
			self.func.static = True

		# parse arguments
		self.func.args = []
		self.func.max_args = len(node.args.args)
		self.func.min_args = self.func.max_args - len(node.args.defaults)

		defaults = [None] * self.func.min_args + node.args.defaults
		args = node.args.args
		for arg in range(len(args)):
			if type(args[arg]) != ast.arg:
				raise Exception("Argument must be a Name")
			if args[arg].arg in list(self.func.all_vars.keys()):
				raise Exception("Two arguments with the same name!")

			size = self.word_size
			init = 0
			flags = 0
			if defaults[arg]:
				if type(defaults[arg]) == Num:
					init = defaults[arg].n

				elif type(arg) == ast.arg and arg.arg in self.consts:
					values.append(self.consts[arg.arg])
				else:
					raise Exception("Unsupported default value")
			self.func.args.append(args[arg].arg)

			# add the new argument
			self.func.all_vars[args[arg].arg] = {	"id":self.func.new_var,
								"type":Function.VAR_UNDEF,
								"size":size,
								"init":init,
								"flags":flags}
			self.func.new_var += 1

		# parse the flow
		body = self._flow_new()
		for obj in node.body:
			self.visit(obj)
			if self.block_stoped:
				break

		self.in_function = False

		self.func.final = self._flow_ret(True)


	def visit_Assign(self, node):
		if len(node.targets) != 1:
			raise Exception("Must be simple targets")

		target = node.targets[0]

		if not self.in_function:
			if type(target) == Name and type(node.value) == Num:
				# this is a constant assignment
				if target.id in self.consts:
					raise Exception("Redefinition of a constant")
				validate_name(target.id)

				self.consts[target.id] = node.value.n
				return
			else:
				raise Exception("All expressions must be in a function")

		if type(target) == Tuple or type(target) == List:
			if type(node.value) != Tuple and type(node.value) != List:
				raise Exception("Value is not iterable")
			if len(node.value.elts) != len(target.elts):
				raise Exception("Not the same number of targets and values")

			# copy the the values to temporary variables and then copy from the temporary variables to the targets
			# the temporary variable's name starts with a "." so they can't be use as a normal variable
			#
			# the reason to do it like this is to allow assignments like:
			#	a,b = b,a
			temp_vars = []
			for el in range(len(target.elts)):
				temp_vars.append(self._get_temp_var())
				self._one_assign(temp_vars[-1], node.value.elts[el])
			for el in range(len(target.elts)):
				self._one_assign(target.elts[el], self.func._get_exp(Function.EXP_VAR, temp_vars[el]), True)
		else:
			# one simple assignment
			self._one_assign(target, node.value)

	def visit_AugAssign(self, node):
		self._one_assign(node.target,
				self.func._get_exp(Function.BINOP[type(node.op)], self.visit(node.target), self.visit(node.value)),
				True)

	def visit_Subscript(self, node):
		# the target may be an buffer offset dereference

		if not self.in_function:
			raise Exception("All expressions must be in a function")

		if type(node.slice) != Index:
			raise Exception("Unsupported dereference type")

		if type(node.value) == Name:
			if node.value.id not in self.func.all_vars:
				raise Exception("Variable used before assignment")

			var = self.func.all_vars[node.value.id]
			if var and (var["type"] == Function.VAR_WORD):
				# we cannot use a word as a pointer
				raise Exception("Invalid dereference")
			return self.func._get_exp(Function.EXP_BUF_OFFSET, var["id"], self.visit(node.slice.value))

		else:
			return self.func._get_exp(Function.EXP_DEREF, self.func._get_exp(Function.EXP_ADD, self.visit(node.value), self.visit(node.slice.value)), 1)

	def visit_Expr(self, node):
		if not self.in_function:
			if 	type(node.value) == Call and \
				node.value.func.id == "VARIABLE_ARGUMENT" and \
				len(node.value.args) == 1 and \
				type(node.value.args[0]) == Str:

				self.variable_argument_funcs.append(node.value.args[0].s)
				return
			elif	type(node.value) == Call and \
				node.value.func.id == "ANONYMOUS" and \
				len(node.value.args) == 1 and \
				type(node.value.args[0]) == Str:
				self.anonymous_funcs.append(node.value.args[0].s)
				return
			elif	type(node.value) == Call and \
				node.value.func.id == "STATIC" and \
				len(node.value.args) == 1 and \
				type(node.value.args[0]) == Str:
				self.static_funcs.append(node.value.args[0].s)
				return
			raise Exception("All expressions must be in a function")
		else:
			if type(node.value) == Call and type(node.value.func) == Name and node.value.func.id in Function.VARNAMES:
				if len(node.value.args) == 0 or type(node.value.args[0]) != Name:
					raise Exception("Wrong syntax of argument definition")
				name = node.value.args[0].id

				typ, size, init, flags = self._parse_builtin_call(node.value, is_expr = True)

				self.func._get_var_id(name, create = True, size = size, typ = typ, init = init, flags = flags)
			else:
				self._create_flow(Function.FLOW_ASSIGN, self.func._get_var_id("_", create = True)["id"], self.visit(node.value))

	def visit_If(self, node):
		if not self.in_function:
			raise Exception("All expressions must be in a function")

		# parse the test expression
		test = self.visit(node.test)

		# parse the "if" flow
		self._flow_new()
		for obj in node.body:
			self.visit(obj)
			if self.block_stoped:
				break
		body = self._flow_ret()

		# parse the "else" flow
		self._flow_new()
		for obj in node.orelse:
			self.visit(obj)
			if self.block_stoped:
				break
		orelse = self._flow_ret()

		self._create_flow(Function.FLOW_IF, test, body, orelse)


	def visit_Pass(self, node):
		pass # :)

	def visit_Try(self, node):
		# parse the "try" flow
		self._flow_new()
		for obj in node.body:
			self.visit(obj)
			if self.block_stoped:
				break
		body = self._flow_ret()

		self._flow_new()
		if len(node.handlers) != 1:
			raise Exception("Unknown try-except parameters")

		# handle the exception variable
		if not node.handlers[0].type is None or not node.handlers[0].name is None:
			if 	type(node.handlers[0].type) == Name and type(node.handlers[0].name) == str:
				name = node.handlers[0].name
				typ = node.handlers[0].type.id
				if typ != 'word' and typ != 'pointer':
					raise Exception("Wrong exception type")
				if name in self.func.all_vars and self.func.all_vars[name]["type"] != Function.VARNAMES[typ]:
					raise Exception("Trying to change a variable's type")
				typ = Function.VARNAMES[typ]

			elif	type(node.handlers[0].type) == Name and node.handlers[0].name is None:
				name = node.handlers[0].type.id
				typ = Function.VARNAMES["word"]
			else:
				raise Exception("Unsupported exception syntax")

			# create the variable if it dosen't exists
			self.func._get_var_id(name, create = True, typ = typ)

			self._one_assign(name, self.func._get_exp(Function.EXP_EXCEPTION_VAR), True)

		# parse the "except" flow
		for obj in node.handlers[0].body:
			self.visit(obj)
			if self.block_stoped:
				break
		handlers = self._flow_ret()

		self._create_flow(Function.FLOW_TRY, body, handlers)

	def visit_While(self, node):
		if not self.in_function:
			raise Exception("All expressions must be in a function")

		# parse the test expression
		test = self.visit(node.test)

		# parse the "while" flow
		self._flow_new()
		for obj in node.body:
			self.visit(obj)
			if self.block_stoped:
				break
		body = self._flow_ret()

		self._create_flow(Function.FLOW_WHILE, test, body)

	def visit_Compare(self, node):
		if not self.in_function:
			raise Exception("All expressions must be in a function")

		left = self.visit(node.left)

		if len(node.ops) != 1 or len(node.comparators) != 1:
			raise Exception("Unsupported compare structure")
		comparators = self.visit(node.comparators[0])
		if type(node.ops[0]) == Lt:
			return self.func._get_exp(Function.EXP_CMP_SIGN, left, comparators)
		if type(node.ops[0]) == LtE:
			invers = self.func._get_exp(Function.EXP_CMP_SIGN, comparators, left)
			return self.func._get_exp(Function.EXP_BOOL_NOT, invers)
		if type(node.ops[0]) == Gt:
			return self.func._get_exp(Function.EXP_CMP_SIGN, comparators, left)
		if type(node.ops[0]) == GtE:
			invers = self.func._get_exp(Function.EXP_CMP_SIGN, left, comparators)
			return self.func._get_exp(Function.EXP_BOOL_NOT, invers)
		if type(node.ops[0]) == Eq:
			return self.func._get_exp(Function.EXP_CMP_EQ, left, comparators)
		if type(node.ops[0]) == NotEq:
			value = self.func._get_exp(Function.EXP_CMP_EQ, left, comparators)
			return self.func._get_exp(Function.EXP_BOOL_NOT, value)

		raise Exception("Unknown operation: %s" % (str(type(node.ops[0])), ))


	def visit_Name(self, node):
		if not self.in_function:
			raise Exception("All expressions must be in a function")

		if node.id in self.consts:
			return self.func._get_exp(Function.EXP_WORD, self.consts[node.id])
		else:
			return self.func._get_exp(Function.EXP_VAR, node.id)

	def visit_Return(self, node):
		if not self.in_function:
			raise Exception("All expressions must be in a function")

		ret = self.visit(node.value)
		self._create_flow(Function.FLOW_RET, ret)
		self.block_stoped = True

	def visit_BinOp(self, node):
		if not self.in_function:
			raise Exception("All expressions must be in a function")

		if type(node.op) == Mod and type(node.left) == Str:
			if type(node.right) == Tuple or type(node.right) == List:
				args = node.right.elts
			else:
				args = [node.right]

			new_args = []
			for arg in args:
				if type(arg) == Name:
					arg = self.func._get_exp(Function.EXP_VAR, arg.id, force = True)
				else:
					arg = self.visit(arg)

				if type(arg) == list:
					arg = self.func._get_exp(Function.EXP_EXP, arg)

				new_args .append(arg)

			ret = [self.func._get_exp(Function.EXP_CALL_PTR, self.func._get_exp(Function.EXP_WORD, self._create_fstring_function(len(args) + 1).addr))]
			ret.append(self.visit(node.left))
			ret += new_args
			ret.append(self.func._get_exp(Function.EXP_CALL_END))
			return ret


		left = self.visit(node.left)
		right = self.visit(node.right)

		return self.func._get_exp(Function.BINOP[type(node.op)], left, right)

	def visit_UnaryOp(self, node):
		if not self.in_function:
			raise Exception("All expressions must be in a function")

		operand = self.visit(node.operand)

		if type(node.op) == USub:
			return self.func._get_exp(Function.EXP_SUB, self.func._get_exp(Function.EXP_WORD, 0), operand)
		else:
			return self.func._get_exp(Function.UNARYOP[type(node.op)], operand)

	def visit_BoolOp(self, node):
		if not self.in_function:
			raise Exception("All expressions must be in a function")

		last_value = self.visit(node.values[0])
		for value in node.values[1:]:
			new_value = self.visit(value)
			last_value = self.func._get_exp(Function.BOOLOP[type(node.op)], last_value, new_value)

		return last_value

	def visit_Call(self, node):
		if not self.in_function:
			raise Exception("All expressions must be in a function")

		if getattr(node, "starargs", None):
			raise Exception("Functions must be simple")

		parse_args = node.args
		if type(node.func) != Name or node.func.id in self.func.all_vars:
			reverse = True
			flags = Function.FUNC_EXTERNAL
			val = self.visit(node.func)
			ret = [self.func._get_exp(Function.EXP_CALL_PTR, val, flags)]

		elif node.func.id == "VARIABLE_ARGUMENT":
			if len(parse_args) == 0:
				raise Exception("VARIABLE function must have an argument")

			reverse = True
			flags = Function.FUNC_EXTERNAL | Function.FUNC_VARIABLE_ARGUMENT

			val = self.visit(parse_args[0])
			parse_args = parse_args[1:]
			ret = [self.func._get_exp(Function.EXP_CALL_PTR, val, flags)]
		else:
			name = node.func.id
			flags = 0
			reverse = False

			if name == "print":
				self.visit_Print(node)
				return self.func._get_exp(Function.EXP_WORD, 0) # return 0

			elif name == "ADDRESSOF" or name == "DEREF":
				if len(node.args) != 1:
					raise Exception("Error using macro %s" % (name, ))

				if type(node.args[0]) != Name:
					if name != "DEREF":
						raise Exception("Error using macro %s" % (name, ))
					return self.func._get_exp(Function.EXP_DEREF, self.visit(node.args[0]), self.word_size)

				try:
					var = self.func._get_var_id(node.args[0].id)
				except:
					raise Exception("Cannot find the address of '%s'" % (node.args[0].id, ))

				if name == "DEREF":
					if var["type"] != Function.VAR_POINTER:
						raise Exception("Can dereference only pointers")
					op = Function.EXP_DEREF
					val2 = self.word_size
				else:
					op = Function.EXP_ADDRESSOF
					val2 = 0
				return self.func._get_exp(op, var["id"], val2)

			elif type(node.func) == Name and node.func.id in ["new", "delete"]:
				if node.func.id == "new":
					is_global = 0
					if len(node.args) == 2:
						if type(node.args[1]) != Num or (node.args[1].n != 0 and node.args[1].n != 1):
							raise Exception("Bad syntax of new")
						is_global = node.args[1].n
					elif len(node.args) != 1:
						raise Exception("Bad syntax of new")

					size = self.visit(node.args[0])

					return self.func._get_exp(Function.EXP_DYN_ALLOC, size, is_global)
				else:
					self._create_flow(Function.FLOW_DYN_FREE, self.visit(node.args[0]))
					return self.func._get_exp(Function.EXP_WORD, 0) # return 0

			elif type(node.func) == Name and node.func.id in ["send", "recv"]:
				if node.func.id == "send":
					if len(node.args) < 1 or len(node.args) > 3:
						raise Exception("Bad syntax of send")

					if type(node.args[0]) != Name:
						raise Exception("send's argument must be a variable")
					try:
						var = self.func._get_var_id(node.args[0].id)
					except:
						raise Exception("Cannot find variable: '%s'" % (node.args[0], ))
					if var["type"] == Function.VAR_WORD:
						raise Exception("Wrong variable type")

					arg2 = 0
					if len(node.args) > 1:
						arg3 = self.visit(node.args[1])
					else:
						arg3 = self.func._get_exp(Function.EXP_WORD, 0)

					if len(node.args) > 2:
						if type(node.args[2]) != Str:
							raise Exception("Third parameter must be a string")
						arg2 = self.func._get_string_value(node.args[2].s)

					self._create_flow(Function.FLOW_SEND_DATA, var["id"], arg2, arg3)
					return self.func._get_exp(Function.EXP_WORD, 0) # return 0
				else:
					if len(node.args) < 1 or len(node.args) > 2:
						raise Exception("Bad syntax of recv")

					if len(node.args) > 1:
						arg2 = self.visit(node.args[1])
					else:
						arg2 = self.func._get_exp(Function.EXP_WORD, 0)

					try:
						var = self.func._get_var_id(node.args[0].id)
						if var["type"] != Function.VAR_POINTER:
							raise
					except:
						raise Exception("Can receive only pointers")

					return self.func._get_exp(Function.EXP_RECV_DATA, var["id"], arg2)

			if name.startswith("KERNEL_"):
				# this is the macro for using external functions
				reverse = True
				name = name[len("KERNEL_"):]
				flags |= Function.FUNC_EXTERNAL
				if node.func.id in self.variable_argument_funcs:
					flags |= Function.FUNC_VARIABLE_ARGUMENT
			ret = [self.func._get_exp(Function.EXP_CALL_STRING, self.func._get_string_value(name), flags)]

		# parse the arguments
		args = []
		for arg in parse_args:
			if type(arg) == Name:
				if arg.id in self.consts:
					val = self.func._get_exp(Function.EXP_WORD, self.consts[arg.id])
				else:
					val = self.func._get_exp(Function.EXP_VAR, arg.id, force = True)
			else:
				val = self.visit(arg)
				if type(val) == list:
					val = self.func._get_exp(Function.EXP_EXP, val)
			args.append(val)

		if reverse:
			# external functions receive there arguments reversed
			args = args[::-1]
		ret += args
		ret.append(self.func._get_exp(Function.EXP_CALL_END))

		return ret

	def visit_Str(self, node):
		return self.func._get_exp(Function.EXP_STRING, self.func._get_string_value(node.s))


	def visit_Num(self, node):
		if not self.in_function:
			raise Exception("All expressions must be in a function")

		return self.func._get_exp(Function.EXP_WORD, node.n)

	def visit_Delete(self, node):
		for target in node.targets:
			self._create_flow(Function.FLOW_DYN_FREE, self.visit(target))

	def visit_Print(self, node):

		def _create_printk(formt, extra = None):
			args = [self.func._get_exp(Function.EXP_CALL_STRING, self.func._get_string_value("printk"), Function.FUNC_EXTERNAL | Function.FUNC_VARIABLE_ARGUMENT)]
			if extra: # reversed order (because it's an external function)
				if type(extra) == list:
					for i in extra[::-1]:
						args.append(self.func._get_exp(Function.EXP_EXP, i))
				else:
					args.append(extra)
			args.append(self.func._get_exp(Function.EXP_STRING, self.func._get_string_value(formt)))
			args.append(self.func._get_exp(Function.EXP_CALL_END))
			self._create_flow(Function.FLOW_ASSIGN, self.func._get_var_id("_", create = True)["id"], args)

		all_formt = ""
		extras = []
		vars = []
		for n in range(len(node.args)):
			if n:
				all_formt += " "
			formt = "%d"
			var = None
			if type(node.args[n]) == Str or (type(node.args[n]) == BinOp and type(node.args[n].op) == Mod and type(node.args[n].left) == Str):
				formt = "%s"
				if type(node.args[n]) == BinOp:
					var = self._get_temp_var()
					self._one_assign(var, node.args[n])
					extra = self.func._get_exp(Function.EXP_VAR, var, force = True)
				else:
					extra = self.visit(node.args[n])
			else:
				if type(node.args[n]) == Name:
					extra = self.func._get_exp(Function.EXP_VAR, node.args[n].id, force = True)
				else:
					extra = self.visit(node.args[n])
			all_formt += formt
			extras.append(extra)
			if var:
				vars.append(var)

		all_formt += "\n"
		_create_printk(all_formt, extras)
		for var in vars:
			self._create_flow(Function.FLOW_DYN_FREE, self.func._get_var_id(var)["id"])


	def visit_Raise(self, node):
		if not self.in_function:
			raise Exception("All expressions must be in a function")

		val = self.visit(node.exc)
		self._create_flow(Function.FLOW_THROW, val)
		self.block_stoped = True

	def visit_NoneType(self, node):
		if not self.in_function:
			raise Exception("All expressions must be in a function")

		return self.func._get_exp(Function.EXP_WORD, 0)


