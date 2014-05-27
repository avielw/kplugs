#include "config.h"
#include "types.h"
#include "function.h"
#include "env.h"
#include "stack.h"
#include "calling.h"

#ifdef DEBUG

static const char *variable_names[] = {
		"word",
		"buffer",
		"array",
		"pointer",
};


static const char *expression_names[] = {
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"+",
		"-",
		"*",
		"/",
		"&",
		"^",
		"|",
		"and",
		"or",
		"~",
		"not ",
		"%",
		"",
		"",
		"",
		"==",
		"<",
		"<",
};

#define DEBUG_PRINT_TABS(num) do { \
	word __i = 0; \
	while (__i < num + 1) { DEBUG_PRINT("\t"); ++__i; } \
} while (0)

#else

#define DEBUG_PRINT_TABS(num) do {} while (0)

#endif

/* recursively checks if the block that starts in index is a valid block */
#define FUNCTION_CHECK_OP(type, index) \
err = function_check_##type(code, len, numvars, checktable, index, max_index, max_string, recur + 1, exception_var); \
if (err < 0) { \
	return err; \
} \
found += err

/* recursively checks if the block that starts in index is a valid flow */
#define CHECK_FLOW(index) FUNCTION_CHECK_OP(flow, index)

/* recursively checks if the block that starts in index is a valid expression */
#define CHECK_EXPRESSION(index) FUNCTION_CHECK_OP(expression, index)


/* check if this opcode has already been checked */

#define CHECK_CHECKTABLE(n) do { \
	if (checktable[n / BITS_PER_BYTE] & (1 << (n % BITS_PER_BYTE))) { \
		ERROR(-ERROR_REFER); \
	} \
} while (0)

#define SET_CHECKTABLE(n) checktable[(n / BITS_PER_BYTE)] |= (1 << (n % BITS_PER_BYTE))

/* check an expression */
static int function_check_expression(	bytecode_t *code,
										word len,
										word numvars,
										byte *checktable,
										word index,
										word *max_index,
										word *max_string,
										word recur,
										word exception_var)
{
	word err = 0;
	word val1 = 0;
	word val2 = 0;
	word found = 0;

	if (recur > MAX_RECUR) {
		ERROR(-ERROR_RECUR);
	}

	if (index >= len) {
		ERROR(-ERROR_OP);
	}


	switch (code[index].op) {
	case OP_VARIABLE:
		if (index >= numvars) {
			ERROR(-ERROR_VAR);
		}

		DEBUG_PRINT("%s%lu", variable_names[code[index].var.type], index);
		return found;

	case OP_EXPRESSION:
		/* check if we were already here */
		CHECK_CHECKTABLE(index);

		SET_CHECKTABLE(index);
		*max_index = MAX(*max_index, index + 1);
		found++;

		val1 = code[index].expression.val1;
		val2 = code[index].expression.val2;

		switch (code[index].expression.type) {
		case EXP_WORD:
			if (val2) {
				ERROR(-ERROR_PARAM);
			}

			DEBUG_PRINT("0x%lx", val1);
			return found;

		case EXP_VAR:
			if (val1 >= numvars || code[val1].var.type == VAR_BUF || code[val1].var.type == VAR_ARRAY) {
				ERROR(-ERROR_VAR);
			}

			if (val2) {
				ERROR(-ERROR_PARAM);
			}

			DEBUG_PRINT("%s%lu", variable_names[code[val1].var.type], val1);

			return found;

		case EXP_STRING:
			if (val1 == 0 || val2) {
				ERROR(-ERROR_PARAM);
			}
			*max_string = MAX(*max_string, val1);

			DEBUG_PRINT("[const%lu]", val1);

			return found;

		case EXP_EXCEPTION_VAR:
			if (val1 || val2 || !exception_var) {
				ERROR(-ERROR_PARAM);
			}

			DEBUG_PRINT("exception_var");

			return found;

		case EXP_ADDRESSOF:
			if (val1 >= numvars) {
				ERROR(-ERROR_VAR);
			}

			if (val2) {
				ERROR(-ERROR_PARAM);
			}

			DEBUG_PRINT("&%s%lu", variable_names[code[val1].var.type], val1);

			return found;

		case EXP_DEREF:
			if (val1 >= len || (val2 != sizeof(byte) && val2 != sizeof(word))) {
				ERROR(-ERROR_PARAM);
			}

			/* if this is a variable you can "dereference" only a pointer */
			if (val1 < numvars && code[val1].var.type != VAR_POINTER) {
				ERROR(-ERROR_VAR);
			}

			DEBUG_PRINT("deref(");

			CHECK_EXPRESSION(val1);

			DEBUG_PRINT(")");

			return found;

		case EXP_BUF_OFFSET:
			if (val1 >= numvars) {
				ERROR(-ERROR_VAR);
			}

			if (	code[val1].var.type != VAR_BUF &&
					code[val1].var.type != VAR_ARRAY &&
					code[val1].var.type != VAR_POINTER) {
					ERROR(-ERROR_VAR);
			}

			DEBUG_PRINT("%s%lu[", variable_names[code[val1].var.type], val1);

			CHECK_EXPRESSION(val2);

			DEBUG_PRINT("]");

			return found;

		case EXP_NOT:
		case EXP_BOOL_NOT:

			if (val2) {
				ERROR(-ERROR_PARAM);
			}

			DEBUG_PRINT("%s", expression_names[code[index].expression.type]);

			CHECK_EXPRESSION(val1);

			return found;

		case EXP_CALL_STRING:
		case EXP_CALL_PTR:

			if (val2 >= FUNC_MAX) {
				ERROR(-ERROR_PARAM);
			}

			if (code[index].expression.type == EXP_CALL_STRING) {
				if (val1 == 0) {
					ERROR(-ERROR_PARAM);
				}

				*max_string = MAX(*max_string, val1);

				DEBUG_PRINT("[const%lu](", val1);


			} else {
				if (val1 >= len) {
					ERROR(-ERROR_PARAM);
				}

				/* if the function is a variable it must be a pointer */
				if (val1 < numvars && code[val1].var.type != VAR_POINTER) {
					ERROR(-ERROR_VAR);
				}

				CHECK_EXPRESSION(val1);

				DEBUG_PRINT("(");
			}

			val1 = 0; /* count the number of arguments */

			/* check the arguments: */

			/* if this is an external function, the arguments will be written in reversed order! */
			do {
				index++;

				if (index >= len) {
					ERROR(-ERROR_OP);
				}

				if (code[index].op != OP_EXPRESSION) {
					ERROR(-ERROR_OP);
				}

				if (code[index].expression.type == EXP_CALL_END) {
					/* check if we were already here */
					CHECK_CHECKTABLE(index);

					SET_CHECKTABLE(index);
					*max_index = MAX(*max_index, index + 1);
					found++;
					break;
				}

#ifdef DEBUG
				if (val1) {
					DEBUG_PRINT(", ");
				}
#endif

				val1++;
				if (val1 > STACK_MAX_PARAMETERS) {
					ERROR(-ERROR_ARGS);
				}

				CHECK_EXPRESSION(index);

			} while (index);

			DEBUG_PRINT(")");

			return found;

		case EXP_CMP_UNSIGN:
			/* we want to print extra data */
			DEBUG_PRINT("unsigned");
		case EXP_ADD:
		case EXP_SUB:
		case EXP_MUL:
		case EXP_DIV:
		case EXP_AND:
		case EXP_OR:
		case EXP_BOOL_AND:
		case EXP_BOOL_OR:
		case EXP_MOD:
		case EXP_CMP_EQ:
		case EXP_CMP_SIGN:
			DEBUG_PRINT("(");

			CHECK_EXPRESSION(val1);

			DEBUG_PRINT(" %s ", expression_names[code[index].expression.type]);

			CHECK_EXPRESSION(val2);

			DEBUG_PRINT(")");

			return found;

		case EXP_DYN_ALLOC:
			if (val2 > 1) { /* should be 0 if local or 1 if global */
				ERROR(-ERROR_PARAM);
			}

			DEBUG_PRINT("new(");

			CHECK_EXPRESSION(val1);

			DEBUG_PRINT(", %ld)", val2);

			return found;

		case EXP_ARGS:
			if (val1 || val2) {
				ERROR(-ERROR_PARAM);
			}

			DEBUG_PRINT("numofArgs");

			return found;

		case EXP_EXP:
			if (val2) {
				ERROR(-ERROR_PARAM);
			}

			CHECK_EXPRESSION(val1);

			return found;
		default:
			ERROR(-ERROR_OP);
		}

	case OP_FLOW:
	default:
		ERROR(-ERROR_OP);
	}
}


/* check a flow */
static int function_check_flow(	bytecode_t *code,
								word len,
								word numvars,
								byte *checktable,
								word index,
								word *max_index,
								word *max_string,
								word recur,
								word exception_var)
{
	int err = 0;
	word found = 0;
	byte block_empty = 1;
	word val1;
	word val2;
	word val3;

	if (recur > MAX_RECUR) {
		ERROR(-ERROR_RECUR);
	}

	if (index >= len) {
		ERROR(-ERROR_OP);
	}


	while (index < len) {
		if (code[index].op >= FLOW_MAX) {
			ERROR(-ERROR_OP);
		}

		switch (code[index].op) {
		case OP_FLOW:

			DEBUG_PRINT_TABS(recur);

			val1 = code[index].flow.val1;
			val2 = code[index].flow.val2;
			val3 = code[index].flow.val3;

			CHECK_CHECKTABLE(index);

			SET_CHECKTABLE(index);
			*max_index = MAX(*max_index, index + 1);
			found++;

			switch (code[index].flow.type) {
			case FLOW_ASSIGN:
				if (	val1 >= numvars ||
						code[val1].var.type == VAR_BUF ||
						code[val1].var.type == VAR_ARRAY) {
					ERROR(-ERROR_VAR);
				}

				if (val3) {
					ERROR(-ERROR_PARAM);
				}

				DEBUG_PRINT("%s%lu = ", variable_names[code[val1].var.type], val1);

				CHECK_EXPRESSION(val2);

				DEBUG_PRINT("\n");

				break;

			case FLOW_ASSIGN_OFFSET:
				if (val1 >= numvars) {
					ERROR(-ERROR_VAR);
				}

				if (	code[val1].var.type != VAR_BUF &&
						code[val1].var.type != VAR_ARRAY &&
						code[val1].var.type != VAR_POINTER) {
					ERROR(-ERROR_VAR);
				}

				DEBUG_PRINT("%s%lu[", variable_names[code[val1].var.type], val1);

				CHECK_EXPRESSION(val2);

				DEBUG_PRINT("] = ");

				CHECK_EXPRESSION(val3);

				DEBUG_PRINT("\n");

				break;

			case FLOW_IF:

				DEBUG_PRINT("if ");

				CHECK_EXPRESSION(val1);

				DEBUG_PRINT(":\n");
				CHECK_FLOW(val2);

				DEBUG_PRINT_TABS(recur);
				DEBUG_PRINT("else:\n");

				CHECK_FLOW(val3);

				break;

			case FLOW_TRY:
				if (val3) {
					ERROR(-ERROR_PARAM);
				}

				DEBUG_PRINT("try:\n");

				CHECK_FLOW(val1);

				DEBUG_PRINT_TABS(recur);
				DEBUG_PRINT("except:\n");

				exception_var++;
				CHECK_FLOW(val2);
				exception_var--;

				break;

			case FLOW_WHILE:
				if (val3) {
					ERROR(-ERROR_PARAM);
				}

				DEBUG_PRINT("while ");

				CHECK_EXPRESSION(val1);

				DEBUG_PRINT(":\n");

				CHECK_FLOW(val2);

				break;


			case FLOW_DYN_FREE:
				if (val2) {
					ERROR(-ERROR_PARAM);
				}

				DEBUG_PRINT("del(");

				CHECK_EXPRESSION(val1);

				DEBUG_PRINT(")\n");

				break;

			case FLOW_BLOCKEND:
				if (val1 || val2 || val3) {
					ERROR(-ERROR_PARAM);
				}


				if (!recur) {
					/* the function must finish with a return or a throw */
					ERROR(-ERROR_OP);
				}

				if (block_empty) {
					DEBUG_PRINT("pass\n\n");
				} else {
					DEBUG_PRINT("\n");

				}

				return found;

			case FLOW_THROW:
				if (val2 || val3) {
					ERROR(-ERROR_PARAM);
				}

				DEBUG_PRINT("throw ");

				CHECK_EXPRESSION(val1);

				DEBUG_PRINT("\n\n");

				return found;

			case FLOW_RET:
				if (!val1 || val2 || val3) {
					ERROR(-ERROR_PARAM);
				}

				DEBUG_PRINT("return ");

				CHECK_EXPRESSION(val1);

				DEBUG_PRINT("\n\n");

				return found;

			default:
				ERROR(-ERROR_OP);
			}

			break;

		case OP_VARIABLE:
		case OP_EXPRESSION:
		default:
			ERROR(-ERROR_OP);
		}

		block_empty = 0;
		index++;
	}

	return -ERROR_FLOW;
}

static int function_check(bytecode_t *code, word len, function_t *func)
{
	word index = 0;
	word found = 0;
	word max_index = 0;
	word max_string = 0;
	word to_add = 0;
	word codelen;
	byte is_arg = 1;
	byte type;
	byte *checktable = NULL;
	byte *strings;
	byte *last_found;
	int err = 0;

	codelen = len / sizeof(bytecode_t);

	if (codelen == 0 || code[0].op != OP_FUNCTION ||
			(code[0].func.return_exception_value && code[0].func.error_return) ||
			code[0].func.function_type >= FUNC_MAX) {
		ERROR(-ERROR_OP);
	}

	max_string = code[0].func.name;
	func->num_minargs = code[0].func.min_args;

	if (func->num_minargs > STACK_MAX_PARAMETERS) {
		ERROR(-ERROR_ARGS);
	}

	checktable = memory_alloc((codelen / BITS_PER_BYTE) + 1);
	if (NULL == checktable) {
		ERROR(-ERROR_MEM);
	}

	memory_set(checktable, 0, (codelen / BITS_PER_BYTE) + 1);

	/* don't let using the first operation */
	SET_CHECKTABLE(0);

	/* count the number of variables */
	for (func->num_vars = 0; func->num_vars < codelen; ++func->num_vars) {
		if (code[func->num_vars + 1].op != OP_VARIABLE) {
			break;
		}
	}

	/* skip the function opcode */
	++index;

	func->total_args_size = 0;
	func->total_vars_size = 0;

#ifdef DEBUG
	if (code[0].func.name) {
		DEBUG_PRINT("def [const%lu](", code[0].func.name);
	} else {
		DEBUG_PRINT("def ANONYMOUS(");
	}
#endif

	/* check the variables declaration */
	while (index < codelen && code[index].op == OP_VARIABLE) {

		if (!is_arg && code[index].var.is_arg) {
			err = -ERROR_PARAM;
			goto clean;
		}
		to_add = 0;
		if (is_arg) {
			if (!code[index].var.is_arg) {

				DEBUG_PRINT("):\n");
				func->num_maxargs = index - 1;
				is_arg = 0;
			} else {
				to_add = sizeof(word);
			}
		}

		type = code[index].var.type;
		if (type >= VAR_MAX) {
			err = -ERROR_OP;
			goto clean;
		}

		switch (type) {
		case VAR_WORD:
		case VAR_POINTER:
			if (code[index].var.size != sizeof(word)) {
				err = -ERROR_PARAM;
				goto clean;
			}

			to_add = sizeof(word);
		case VAR_BUF:
			if (to_add == 0) {
				to_add = sizeof(word) + code[index].var.size;
			}
			break;
		case VAR_ARRAY:
			if (code[index].var.size % sizeof(word)) {
				err = -ERROR_PARAM;
				goto clean;
			}
			if (to_add == 0) {
				to_add = sizeof(word) + code[index].var.size;
			}

			break;

		default:
			err = -ERROR_OP;
			goto clean;
		}

#ifdef DEBUG
		if (is_arg) {
			if (index > 1) {
				DEBUG_PRINT(", ");
			}
			DEBUG_PRINT("%s%lu", variable_names[type], index);
			if (func->num_minargs < index) {
				DEBUG_PRINT(" = %ld", (sword)code[index].var.init);
			}
		} else {
			DEBUG_PRINT("\t%s%lu", variable_names[type], index);
			if (type == VAR_ARRAY || type == VAR_BUF) {
				DEBUG_PRINT(" = %s(%lu)\n", variable_names[type], code[index].var.size / ((type == VAR_ARRAY) ? sizeof(word) : sizeof(byte)));
			} else {
				DEBUG_PRINT(" = %s(%ld)\n", variable_names[type], (sword)code[index].var.init);
			}
		}
#endif

		if (to_add % sizeof(word)) {
			/* round up */
			to_add += sizeof(word) - (to_add % sizeof(word));
		}

		if (to_add > MAX_STACK_FRAME || to_add + func->total_vars_size > MAX_STACK_FRAME) {
			err = -ERROR_MEM;
			goto clean;
		}

		if (is_arg) {
			func->total_args_size += to_add;
		}
		func->total_vars_size += to_add;

		SET_CHECKTABLE(index);

		index++;
	}

	if (is_arg) {
		DEBUG_PRINT("):\n");
		func->num_maxargs = index - 1;
	}
	if (func->num_maxargs > STACK_MAX_PARAMETERS || func->num_maxargs < func->num_minargs) {
		err = -ERROR_ARGS;
		goto clean;
	}


	/* check the code's flow */
	max_index = index;
	if (index < codelen) {

		DEBUG_PRINT("\n");

		err = function_check_flow(code, codelen, index, checktable, index, &max_index, &max_string, 0, 0);

		CHECK_ERROR(err);

		if (err != max_index - index) {
			err = (err < 0) ? err : -ERROR_EXPLO;
			goto clean;
		}
	}

	/* check the strings constants */
	func->num_opcodes = max_index;

	if (max_string * sizeof(word) < max_string) {
		/* integer overflow... */
		err = -ERROR_PARAM;
		goto clean;
	}

	func->string_table = memory_alloc(max_string * sizeof(word));
	if (NULL == func->string_table) {
		err = -ERROR_MEM;
		goto clean;
	}

	strings = (byte *)&code[max_index];
	last_found = strings;
	len -= max_index * sizeof(bytecode_t);
	index = 0;
	found = 0;

	DEBUG_PRINT("\n");

	while (index < len) {
		if (strings[index] == '\0') {
			if (found < max_string) {
				func->string_table[found] = (last_found - strings) + (max_index * sizeof(bytecode_t));
			}

			found++;
			DEBUG_PRINT("const%lu = \"%s\"\n", found, last_found);

			last_found = &strings[index + 1];
		}
		index++;
	}
	/* the last one is not counted if it's not null terminated */

	if (max_string > found) {
		err = -ERROR_PARAM;
	} else {
		err = 0;
	}

clean:
	if (NULL != checktable) {
		memory_free(checktable);
	}

	if (err < 0) {
		if (func->string_table) {
			memory_free(func->string_table);
			func->string_table = NULL;
		}

	}

	if (err < 0) {
		ERROR(err);
	}
	return 0;
}

/* check if a function's name is valid */
static int function_check_name(function_t *func)
{
	word iter = 0;

	for (iter = 0; func->name[iter]; ++iter) {
		if (func->name[iter] >= 'a' && func->name[iter] <= 'z') {
			continue;
		}
		if (func->name[iter] >= 'A' && func->name[iter] <= 'Z') {
			continue;
		}
		if (func->name[iter] >= '_') {
			continue;
		}
		if (iter != 0 && func->name[iter] >= '0' && func->name[iter] <= '9') {
			continue;
		}
		ERROR(-ERROR_NAME);
	}

	if (iter == 0) {
		ERROR(-ERROR_NAME);
	}
	return 0;
}

/* create a function */
int function_create(bytecode_t *code, word len, function_t **func)
{
	int err = 0;

	/* the function must be executable because of the wrapper inside it */
	*func = memory_alloc_exec(sizeof(function_t) + ((word)&wrapper_end - (word)&wrapper_start));
	if (NULL == *func) {
		ERROR(-ERROR_MEM);
	}

	memory_set(*func, 0, sizeof(function_t));
	atomic_set(&(*func)->ref_count, 1);

	err = function_check(code, len, *func);
	if (err < 0) {
		goto clean;
	}

	/* set the function wrapper's callback */
	(*func)->code = code;
	memory_copy((*func)->func_code, &wrapper_start, ((word)&wrapper_end - (word)&wrapper_start));
	if ((*func)->code[0].func.function_type == FUNC_VARIABLE_ARGUMENT) {
		*(word *)GET_FUNCTION_CALLBACK(*func) = (word)variable_argument_function_callback;
	} else {
		*(word *)GET_FUNCTION_CALLBACK(*func) = (word)standard_function_callback;
	}
	err = 0;


	if (code[0].func.name) {
		(*func)->name = (char *)((*func)->raw) + (*func)->string_table[code[0].func.name - 1];

		err = function_check_name(*func);
	}
clean:
	if (err < 0 && *func) {
		if ((*func)->string_table) {
			memory_free((*func)->string_table);
		}
		memory_free_exec(*func);
		*func = NULL;
	}

	return err;
}

/* increasing the refcount by one */
void function_get(function_t *func)
{
	atomic_inc(&func->ref_count);
}

/* decreasing the refcount by one - and freeing if the refcount is zero */
void function_put(function_t *func)
{
	if (atomic_dec_and_test(&func->ref_count)) {
		DEBUG_PRINT("Deleting function: %p\n", func);
		memory_free(func->string_table);
		memory_free(func->raw);
		memory_free_exec(func);
	}
}

