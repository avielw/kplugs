#ifndef CALLING_H
#define CALLING_H

#include "stack.h"
#include "config.h"

/* defined in calling_wrapper.S */
extern word wrapper_start;
extern word wrapper_end;
extern word wrapper_callback;
extern void wrapper_unlock(void);
extern word wrapper_curfunc;


#define GET_FUNCTION_CALLBACK(func) ((func)->func_code + ((word)&wrapper_callback - (word)&wrapper_start))

#if STACK_MAX_PARAMETERS > 15
#error "STACK_MAX_PARAMETERS don't much the defining of the functions prototype"
#else

#define STANDARD_FUNC_VARIABLES word var1, word var2, word var3, word var4, word var5, word var6, word var7, word var8, word var9, word var10, word var11, word var12, word var13, word var14, word var15
#define VARIBALES_LIST var1, var2, var3, var4, var5, var6, var7, var8, var9, var10, var11, var12, var13, var14, var15


/* the calling conventions type.
 * because it is always the caller responsibility to clean the arguments we don't have to know exactly the
 * number of arguments that the function we call receive */
typedef word (standard_function_t)(STANDARD_FUNC_VARIABLES);
typedef word (variable_argument_function_t)(word first_var, ...);

/* call an external function (not a vm function) */
word call_external_function(void *external_function, kpstack_t *arg_stack, word flags);



/* we arrive to that function through the wrapper if it's a standard function */
standard_function_t standard_function_callback;

/* we arrive to that function through the wrapper if it's a variable argument function */
variable_argument_function_t variable_argument_function_callback;

#endif

#endif
