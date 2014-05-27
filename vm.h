#ifndef VM_H
#define VM_H

#include "types.h"
#include "function.h"
#include "context.h"
#include "stack.h"
#include "config.h"
#include "calling.h"
#include "cache.h"

typedef enum {
	VM_FLOW,
	VM_EXPRESSION,
} vm_ops_t;

typedef struct {
	byte op;
	word pc;
	sword stage;

	word args;
	function_t *func;

	word *vars;
	arg_cache_t *cache;

	word val;
	word exception_handler;
} vm_state_t;

/* execute a function on the vm */
word vm_run_function(function_t *func, stack_t *arg_stack, exception_t *excep);

#endif
