#ifndef FUNCTION_H
#define FUNCTION_H

#include "stack.h"
#include "config.h"
#include "types.h"
#include "context.h"


/* operator types */
typedef enum {
	OP_FUNCTION,
	OP_VARIABLE,
	OP_FLOW,
	OP_EXPRESSION,

	/* we don't need OP_MAX because the opcode is only two bits */
} opcode_t;


/* variable types */
typedef enum {
	VAR_WORD,
	VAR_BUF,
	VAR_ARRAY,
	VAR_POINTER,

	VAR_MAX,

} vartypes_t;


/* expression types */
typedef enum {
	EXP_WORD,
	EXP_VAR,
	EXP_STRING,
	EXP_EXCEPTION_VAR,

	EXP_ADDRESSOF,
	EXP_DEREF,

	EXP_BUF_OFFSET,
	EXP_ADD,
	EXP_SUB,
	EXP_MUL,
	EXP_DIV,
	EXP_AND,
	EXP_XOR,
	EXP_OR,
	EXP_BOOL_AND,
	EXP_BOOL_OR,
	EXP_NOT,
	EXP_BOOL_NOT,
	EXP_MOD,
	EXP_CALL_STRING,
	EXP_CALL_PTR,
	EXP_CALL_END,
	EXP_CMP_EQ,
	EXP_CMP_UNSIGN,
	EXP_CMP_SIGN,

	EXP_DYN_ALLOC, /* allocate a dynamic buffer */

	EXP_ARGS, /* the number of arguments that was received */
	EXP_EXP, /* poitner to an expression. used in case of a function call in a function argument */

	EXP_MAX,
} expressiontypes_t;


/* flow types */
typedef enum {
	FLOW_ASSIGN,
	FLOW_ASSIGN_OFFSET,
	FLOW_IF,
	FLOW_TRY,
	FLOW_WHILE,
	FLOW_DYN_FREE, /* free a dynamic buffer */

	/* block terminators */
	FLOW_BLOCKEND,
	FLOW_THROW,
	FLOW_RET,

	FLOW_MAX,
} flowtypes_t;


/* function special types */
typedef enum {
	FUNC_VARIABLE_ARGUMENT	= 1 << 0,
	FUNC_EXTERNAL 			= 1 << 1,

	FUNC_MAX = (FUNC_VARIABLE_ARGUMENT | FUNC_EXTERNAL) + 1,
} function_types_t;


/* a function code */
typedef struct {
	byte op   : 2;

	byte min_args : 5;
	byte return_exception_value : 1;
	word name;
	word error_return;
	byte function_type;
} bytecode_func_t;


/* a variable code */
typedef struct {
	byte op   : 2;

	byte type : 5;
	byte is_arg : 1;
	word size;
	word init;
	byte flags;
} bytecode_var_t;


/* an expression code */
typedef struct {
	byte op   : 2;

	byte type : 6;
	word val1;
	word val2;
} bytecode_expression_t;


/* a flow code */
typedef struct {
	byte op   : 2;

	byte type : 6;
	word val1;
	word val2;
	word val3;
} bytecode_flow_t;


/* one bytecode structure */
typedef union {
	byte op : 2;

	bytecode_func_t func;
	bytecode_var_t var;
	bytecode_expression_t expression;
	bytecode_flow_t flow;
} bytecode_t;


/* a function struct */
typedef struct {
	list_head_t list;
	atomic_t ref_count;

	char *name;		/* name */
	context_t *cont;	/* context */

	/* a copy of the bytecode of this function */
	union {
		bytecode_t *code;
		byte *raw;
	};

	word num_minargs;	/* minimum number of arguments number */
	word num_maxargs;	/* maximum number of arguments number */
	word num_vars;		/* variables number */
	word num_opcodes;	/* number of opcodes */

	word total_args_size;	/* the size of memory needed to store the arguments */
	word total_vars_size;	/* the size of memory needed to store the all the variables (including the arguments) */

	word *string_table;		/* points to the string table (the offset of every string in the string's section in the bytecode) */

	byte func_code[];		/* the function's wrapper */
} function_t;

/* create a function */
int function_create(bytecode_t *code, word len, function_t **func);

/* increasing the refcount by one */
void function_get(function_t *func);

/* decreasing the refcount by one - and freeing if the refcount is zero */
void function_put(function_t *func);


/* defined in context.c : */

/* add a function to a context */
int context_add_function(context_t *cont, function_t *func);

/* remove and delete a function from the context */
void context_free_function(function_t *func);

#endif
