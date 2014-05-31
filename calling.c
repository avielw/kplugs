#include "env.h"

#include "types.h"
#include "function.h"
#include "calling.h"
#include "vm.h"

#if STACK_MAX_PARAMETERS > 15
#error "STACK_MAX_PARAMETERS don't match the defining of the functions prototype"
#else


/* push one argument to the arguments stack */
#define FUNC_PUSH_ARG(num) do { \
	if (iter >= func->num_maxargs) { \
		goto end; \
	} \
	if (NULL == stack_push(&arg_stack, &var##num)) { \
		stack_free(&arg_stack); \
		ERROR(-ERROR_MEM); \
	} \
	iter++; \
} while (0)


/* we arrive to that function through the wrapper if it's a standard function */
word standard_function_callback(STANDARD_FUNC_VARIABLES)
{
	/* get the function struct from wrapper_curfunc */
	function_t *func = (function_t *)(wrapper_curfunc - offsetof(function_t, func_code));
	word ret = 0;
	word iter = 0;
	int err;
	stack_t arg_stack;
	exception_t excep;

	/* the wrapper has waited for us to get the function struct. now we can unlock it */
	wrapper_unlock();

	/* we don't really need it, but it can help avoiding race conditions if it is used incorrectly */
	function_get(func);

	err = stack_alloc(&arg_stack, sizeof(word), CALL_STACK_SIZE);
	if (err < 0) {
		function_put(func);
		return (word)err;
	}

	/* put all the arguments in the stack */
	FUNC_PUSH_ARG(1);
	FUNC_PUSH_ARG(2);
	FUNC_PUSH_ARG(3);
	FUNC_PUSH_ARG(4);
	FUNC_PUSH_ARG(5);
	FUNC_PUSH_ARG(6);
	FUNC_PUSH_ARG(7);
	FUNC_PUSH_ARG(8);
	FUNC_PUSH_ARG(9);
	FUNC_PUSH_ARG(10);
	FUNC_PUSH_ARG(11);
	FUNC_PUSH_ARG(12);
	FUNC_PUSH_ARG(13);
	FUNC_PUSH_ARG(14);
	FUNC_PUSH_ARG(15);

end:

	/* execute the function on the vm */
	ret = vm_run_function(func, &arg_stack, &excep);

	stack_free(&arg_stack);

	function_put(func);

	return ret;	
}

/* we arrive to that function through the wrapper if it's a variable argument function */
word variable_argument_function_callback(word first_var, ...)
{
	/* get the function struct from wrapper_curfunc */
	function_t *func = (function_t *)(wrapper_curfunc - offsetof(function_t, func_code));
	word ret = 0;
	word iter = 0;
	int err;
	va_list ap;
	stack_t arg_stack;
	exception_t excep;

	/* the wrapper has waited for us to get the function struct. now we can unlock it */
	wrapper_unlock();

	/* we don't really need it, but it can help avoiding race conditions if it is used incorrectly */
	function_get(func);

	err = stack_alloc(&arg_stack, sizeof(word), CALL_STACK_SIZE);
	if (err < 0) {
		function_put(func);
		return (word)err;
	}

	/* put all the arguments in the stack */

	va_start(ap, first_var);

	for (iter = 0; iter < func->num_maxargs; ++iter) {
		ret = (iter == 0) ? first_var : va_arg(ap, word);
		if (NULL == stack_push(&arg_stack, &ret)) {
			ERROR_CLEAN(-ERROR_MEM);
		}
	}

	va_end(ap);

	/* execute the function on the vm */
	ret = vm_run_function(func, &arg_stack, &excep);

clean:
	stack_free(&arg_stack);

	function_put(func);

	if (err < 0) {
		return (word)err;
	}

	return ret;
}

/* pop an argument from the arguments stack and put it in the right variable */
#define FUNC_POP_ARG(num) do { \
	if (stack_pop(arg_stack, &var##num)) { \
		goto end; \
	} \
} while (0)


/* call an external function (not a vm function) */
word call_external_function(void *external_function, stack_t *arg_stack, word flags)
{
	standard_function_t *s_function = external_function;
	variable_argument_function_t *va_function = external_function;
	word var1 = 0;
	word var2 = 0;
	word var3 = 0;
	word var4 = 0;
	word var5 = 0;
	word var6 = 0;
	word var7 = 0;
	word var8 = 0;
	word var9 = 0;
	word var10 = 0;
	word var11 = 0;
	word var12 = 0;
	word var13 = 0;
	word var14 = 0;
	word var15 = 0;

	/* get the arguments from the stack */
	FUNC_POP_ARG(1);
	FUNC_POP_ARG(2);
	FUNC_POP_ARG(3);
	FUNC_POP_ARG(4);
	FUNC_POP_ARG(5);
	FUNC_POP_ARG(6);
	FUNC_POP_ARG(7);
	FUNC_POP_ARG(8);
	FUNC_POP_ARG(9);
	FUNC_POP_ARG(10);
	FUNC_POP_ARG(11);
	FUNC_POP_ARG(12);
	FUNC_POP_ARG(13);
	FUNC_POP_ARG(14);
	FUNC_POP_ARG(15);

end:

	/* call the function */
	return (flags & FUNC_VARIABLE_ARGUMENT) ? va_function(VARIBALES_LIST) : s_function(VARIBALES_LIST);
}

#endif
