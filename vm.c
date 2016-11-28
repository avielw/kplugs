#include "vm.h"
#include "function.h"
#include "stack.h"
#include "env.h"

/* restore a state when returning from a function */
#define STATE_RESTORE(func) do { \
	if (cache) { \
		cache_clean(cache, calling_function->num_maxargs); \
		memory_free(cache); \
	} \
	if (vars) { \
		memory_free(vars); \
	} \
	function_put(func); \
	vars = state->vars; \
	cache = state->cache; \
	state->vars = NULL; \
	state->cache = NULL; \
	recur--; \
} while (0)
			
/* calling a KPlugs function using the VM */
#define VM_CALL(new_func) do { \
	if (recur >= MAX_CALL_RECUR) { \
		function_put(new_func); \
		VM_THROW_EXCEPTION(ERROR_RECUR); \
	} \
	recur++; \
	state->vars = vars; \
	state->cache = cache; \
	vars = memory_alloc(new_func->num_vars * sizeof(word)); \
	if (NULL == vars) { \
		vars = state->vars; \
		recur--; \
		function_put(new_func); \
		VM_THROW_EXCEPTION(ERROR_MEM); \
	} \
	cache = memory_alloc(new_func->num_maxargs * sizeof(arg_cache_t)); \
	if (NULL == cache) { \
		STATE_RESTORE(new_func); \
		VM_THROW_EXCEPTION(ERROR_MEM); \
	} \
	cache_init(cache, new_func->num_maxargs); \
	new_state = push_state(new_func, &stack, new_func->num_vars + 1, 0); \
	if (NULL == new_state) { \
		STATE_RESTORE(new_func); \
		VM_THROW_EXCEPTION(ERROR_MEM); \
	} \
	state = new_state; \
	err = vm_init_local_variable(state, arg_stack, vars, cache); \
	if (err < 0) { \
		VM_THROW_EXCEPTION(err); \
	} \
} while (0); continue


/* throw an exception */
#define VM_THROW_EXCEPTION(val) do { \
	exception_var = val; \
	excep->pc = state->pc; \
	excep->func = (word)&(state->func->func_code); \
	while (state->op != VM_FLOW || state->exception_handler == 0) { \
		DEBUG_PRINT("EXCEPTION: Return from PC: 0x%lx stage: %ld\n", state->pc, state->stage); \
		err = stack_pop(&stack, NULL); \
		CHECK_ERROR(err); \
		if (stack_is_empty(&stack)) { \
			err = 0; \
			ret = state->func->code[0].func.return_exception_value ? exception_var : state->func->code[0].func.error_return; \
			DEBUG_PRINT("Unhandled exception: return %lx\n", ret); \
			excep->had_exception = 1; \
			excep->value = exception_var; \
			goto clean; \
		} \
		calling_function = state->func; \
		state = stack_peek(&stack); \
		if (NULL == state) { \
			ERROR_CLEAN(-ERROR_SEMPTY); \
		} \
		if (	state->func->code[state->pc].op == OP_EXPRESSION && \
				(state->func->code[state->pc].flow.type == EXP_CALL_STRING || \
				 state->func->code[state->pc].flow.type == EXP_CALL_PTR) && \
				state->vars != NULL) { \
			STATE_RESTORE(calling_function); \
		} \
	} \
	temp_value = state->exception_handler; \
	state->exception_handler = 0; \
	load_state(func, state, state->pc + 1, state->args); \
	state->stage--; \
} while (0); VM_ENTER_BLOCK(temp_value)


/* one vm step */
#define VM_STEP() do { \
	state->pc++; \
	state->stage = 0; \
} while (0); continue


/* enter a new block */
#define VM_ENTER_BLOCK(new_pc) do { \
	state = push_state(state->func, &stack, new_pc, state->args); \
	if (NULL == state) { \
		ERROR_CLEAN(-ERROR_MEM); \
	} \
} while (0); continue


/* leave the current block */
#define VM_LEAVE_BLOCK() do { \
	err = stack_pop(&stack, NULL); \
	CHECK_ERROR(err); \
	if (!stack_is_empty(&stack)) { \
		state = stack_peek(&stack); \
		if (NULL == state) { \
			ERROR_CLEAN(-ERROR_SEMPTY); \
		} \
		state->stage++; \
	} \
} while (0); continue


/* return from this function */
#define VM_RET(value) do { \
	while (1) { \
		DEBUG_PRINT("Return from PC: 0x%lx stage: %ld\n", state->pc, state->stage); \
		err = stack_pop(&stack, NULL); \
		CHECK_ERROR(err); \
		if (stack_is_empty(&stack)) { \
			DEBUG_PRINT("The function has terminated: return 0x%lx\n", value); \
			goto clean; \
		} \
		calling_function = state->func; \
		state = stack_peek(&stack); \
		if (NULL == state) { \
			ERROR_CLEAN(-ERROR_SEMPTY); \
		} \
		if (	state->func->code[state->pc].op == OP_EXPRESSION && \
				(state->func->code[state->pc].flow.type == EXP_CALL_STRING || \
				 state->func->code[state->pc].flow.type == EXP_CALL_PTR) && \
				state->vars != NULL) { \
			/* we should always get here */ \
			STATE_RESTORE(calling_function); \
			ret = value; \
			DEBUG_PRINT("Return value: 0x%lx\n", value); \
			break; \
		} \
	} \
} while (0); VM_LEAVE_BLOCK()


/* load a state from a function and a pc */
static void load_state(function_t *func, vm_state_t *state, word pc, word num_args)
{
	memory_set(state, 0, sizeof(vm_state_t));

	state->op = (func->code[pc].op == OP_FLOW) ? VM_FLOW : VM_EXPRESSION;
	state->pc = pc;
	state->func = func;
	state->args = num_args;
}

/* push a state in the state stack */
static vm_state_t *push_state(function_t *func, kpstack_t *stack, word pc, word num_args)
{
	vm_state_t state;

	load_state(func, &state, pc, num_args);
	return stack_push(stack, &state);
}

/* initialize the arguments and local variables buffer */
static int vm_init_local_variable(vm_state_t *state, kpstack_t *arg_stack, word *vars, arg_cache_t *cache)
{
	word iter = state->func->num_maxargs;
	word iter2 = 0;
	word init;
	word data_offset = sizeof(word) * state->func->num_vars;

	state->args = 0;

	/* load the arguments (in reversed order) */
	while ((!stack_pop(arg_stack, &vars[iter - 1])) && iter > 0) {
		iter--;
		state->args++;
	}

	/* check that we loaded enough arguments and all the arguments  */
	if (state->args < state->func->num_minargs || !stack_is_empty(arg_stack)) {
		return -ERROR_ARGS;
	}

	if (state->args != state->func->num_maxargs) {
		/* fix the pointers */
		for (iter = 0; iter < state->args; ++iter) {
			vars[iter] = vars[iter + (state->func->num_maxargs - state->args)];
		}
	}

#ifdef DEBUG
	for (iter = 0; iter < state->args; ++iter) {
		if (iter != 0) {
			DEBUG_PRINT(", ");
		}
		DEBUG_PRINT("%lx", *(word *)&vars[iter]);
	}

	DEBUG_PRINT(")\n");

#endif

	/* initialize all the default arguments values and the local variables */
	for (iter = state->args; iter < state->func->num_vars; ++iter) {
		init = state->func->code[iter + 1].var.init;

		if (	state->func->code[iter + 1].var.type == VAR_WORD ||
			state->func->code[iter + 1].var.type == VAR_POINTER) {

			/* initialize words and pointers */
			vars[iter] = init;

		} else {
			/* make the array to point to its data in the buffer */
			vars[iter] = (word)(((byte *)vars) + data_offset);
			data_offset += state->func->code[iter + 1].var.size;

			data_offset = ROUNDUP(data_offset, sizeof(word));

			if (state->func->code[iter + 1].var.type == VAR_BUF) {
				/* buffer */
				memory_set((byte *)vars[iter], init, state->func->code[iter + 1].var.size);
			} else {

				/* array */

				/* we initialize every word */
				for (	iter2 = 0;
						iter2 < (state->func->code[iter + 1].var.size / sizeof(word));
						++iter2) {
					((word *)(vars[iter]))[iter2] = init;
				}
			}
		}
	}

	return 0;
}

extern context_t *GLOBAL_CONTEXT;

/* execute a function on the vm */
word vm_run_function(function_t *func, kpstack_t *arg_stack, exception_t *excep)
{
	word pc;
	sword stage;
	word *vars = NULL;
	arg_cache_t *cache = NULL;
	dyn_mem_t dyn_head;

	vm_state_t *state;
	vm_state_t *new_state;
	kpstack_t stack;

	function_t *calling_function = NULL;
	void *external_function = NULL;
	dyn_mem_t *dyn;
	word recur = 0;
	word type = 0;
	word val1 = 0;
	word val2 = 0;
	word val3 = 0;
	word temp_value = 0, temp_value2 = 0;
	word exception_var = 0;
	word ret = 0;
	byte ret_b = 0;

	int err = 0;

	excep->had_exception = 0;

	err = stack_alloc(&stack, sizeof(vm_state_t), CALL_STACK_SIZE);
	if (err < 0) {
		return err;
	}

	memory_dyn_init(&dyn_head);

	vars = memory_alloc(func->total_vars_size);
	if (NULL == vars) {
		ERROR_CLEAN(-ERROR_MEM);
	}

	cache = memory_alloc(func->num_maxargs * sizeof(arg_cache_t));
	if (NULL == cache) {
		ERROR_CLEAN(-ERROR_MEM);
	}

	cache_init(cache, func->num_maxargs);

	state = push_state(func, &stack, func->num_vars + 1, 0);
	if (NULL == state) { \
		ERROR_CLEAN(-ERROR_MEM);
	}


#ifdef DEBUG
	if (func->code[0].func.name) {
		DEBUG_PRINT("Starting a VM function: %s(",
				func->raw + func->string_table[func->code[0].func.name - 1]);
	} else {
		DEBUG_PRINT("Starting a VM anonymous function: %p(",
				func->func_code);
	}
#endif

	/* load the arguments and local variable */
	err = vm_init_local_variable(state, arg_stack, vars, cache);
	CHECK_ERROR(err);

	while (!stack_is_empty(&stack)) {

		pc = state->pc;
		stage = state->stage;

		if (pc > 0 && pc < state->func->num_vars + 1) {
			switch (state->func->code[pc].var.type) {
			case VAR_WORD:
			case VAR_POINTER:
				ret = vars[pc - 1];
				VM_LEAVE_BLOCK();
			break;
			default:
				VM_THROW_EXCEPTION(ERROR_VAR);
			}
		}

		switch (state->op) {
		case VM_FLOW:
			type = state->func->code[pc].flow.type;
			val1 = state->func->code[pc].flow.val1;
			val2 = state->func->code[pc].flow.val2;
			val3 = state->func->code[pc].flow.val3;

			switch (type) {
			case FLOW_ASSIGN:
				if (stage == 0) {
					VM_ENTER_BLOCK(val2);
				} else {
					vars[val1 - 1] = ret;
					VM_STEP();
				}

			break;

			case FLOW_ASSIGN_OFFSET:
				if (stage == 0) {
					VM_ENTER_BLOCK(val3);
				} else if (stage == 1) {
					state->val = ret;

					VM_ENTER_BLOCK(val2);
				} else {



					if (state->func->code[val1].var.type == VAR_POINTER) {
						temp_value = sizeof(byte);
						temp_value2 = ret;
					} else if (state->func->code[val1].var.type == VAR_BUF) {
						if (temp_value2 >= state->func->code[val1].var.size) {
							VM_THROW_EXCEPTION(ERROR_OOB);
						}

						temp_value = sizeof(byte);
						temp_value2 = ret;
					} else {

						/* VAR_ARRAY */

						temp_value = sizeof(word);
						temp_value2 = ret * temp_value;

						/* because of the alignment we can't overflow */
						if (temp_value2 >= state->func->code[val1].var.size) {
							VM_THROW_EXCEPTION(ERROR_OOB);
						}

					}

					if (state->func->code[val1].var.type != VAR_POINTER) {

						if (val1 > state->args) {
							/* This is NOT a pointer and it's a local variable */
							if (temp_value == sizeof(word)) {
								*(word *)(vars[val1 - 1] + temp_value2) = state->val;
							} else {
								*(byte *)(vars[val1 - 1] + temp_value2) = (byte)state->val;
							}
							err = 0;
						} else {
							/* This is NOT a pointer and it's an argument */
							err = cache_memory_copy((byte *)vars[val1 - 1], (byte *)&state->val, temp_value2, temp_value, state->func->code[val1].var.size, &cache[val1 - 1], 1);
						}
					} else {
						/* This is a pointer */

						/* check if it's a dynamic memory */
						dyn = get_dyn_mem(&dyn_head, (void *)vars[val1 - 1]);
						if (NULL != dyn) {
							/* we can check boundaries */
							if (temp_value2 >= dyn->size) {
								VM_THROW_EXCEPTION(ERROR_OOB);
							}
							*(byte *)(vars[val1 - 1] + temp_value2) = (byte)state->val;
						} else {
							err = safe_memory_copy(((byte *)vars[val1 - 1]) + temp_value2, &state->val, temp_value, ADDR_UNDEF, ADDR_INSIDE, 0, 0);
						}
					}

					if (err < 0) {
						VM_THROW_EXCEPTION(-err);
					}

					VM_STEP();
				}

			break;
			case FLOW_IF:
				if (stage == 0) {
					VM_ENTER_BLOCK(val1);
				} else if (stage == 1) {
					if (ret) {
						VM_ENTER_BLOCK(val2);
					} else {
						VM_ENTER_BLOCK(val3);
					}
				} else {
					VM_STEP();
				}

			break;

			case FLOW_TRY:
				if (stage == 0) {
					state->exception_handler = val2;
					VM_ENTER_BLOCK(val1);
				} else {
					VM_STEP();
				}

			break;

			case FLOW_WHILE:
				if (stage == 0) {
					VM_ENTER_BLOCK(val1);
				} else if (stage == 1) {
					if (ret) {
						VM_ENTER_BLOCK(val2);
					} else {
						VM_STEP();
					}
				} else {
					state->stage = 0;
				}

			break;

			case FLOW_DYN_FREE:
				if (stage == 0) {
					VM_ENTER_BLOCK(val1);
				} else {
					err = memory_free_dyn(val2 ? NULL : &dyn_head, (void *)ret);
					if (err) {
						VM_THROW_EXCEPTION(-err);
					}
					VM_STEP();
				}

			break;

			case FLOW_BLOCKEND:
				VM_LEAVE_BLOCK();

			break;

			case FLOW_THROW:
				if (stage == 0) {
					VM_ENTER_BLOCK(val1);
				} else {
					VM_THROW_EXCEPTION(ret);
				}

			break;

			case FLOW_RET:
				if (stage == 0) {
					VM_ENTER_BLOCK(val1);
				} else {
					VM_RET(ret);
				}

			break;


			default:
				/* we should never get here! */
				VM_THROW_EXCEPTION(ERROR_OP);
			break;
			}
		break;
		case VM_EXPRESSION:
			type = state->func->code[pc].expression.type;
			val1 = state->func->code[pc].expression.val1;
			val2 = state->func->code[pc].expression.val2;
			switch (type) {
			case EXP_WORD:
				ret = val1;
				VM_LEAVE_BLOCK();

			break;

			case EXP_VAR:
				ret = vars[val1 - 1];
				VM_LEAVE_BLOCK();

			break;

			case EXP_STRING:
				ret = (word)state->func->raw + state->func->string_table[val1 - 1];
				VM_LEAVE_BLOCK();

			break;

			case EXP_EXCEPTION_VAR:
				ret = exception_var;
				VM_LEAVE_BLOCK();

			break;

			case EXP_ADDRESSOF:
				if (	state->func->code[val1].var.type == VAR_WORD || 
						state->func->code[val1].var.type == VAR_POINTER) {
					ret = (word)&vars[val1 - 1];
				} else {
					if (val1 > state->args) {
						/* this is a local variable */
						ret = vars[val1 - 1];
					} else {
						/* this is a buffer/array argument */
						if (!IS_CACHED(&cache[val1 - 1])) {
							err = cache_memory_map((byte *)vars[val1 - 1], state->func->code[val1].var.size, &cache[val1 - 1], 0);
							if (err < 0) {
								/* we cannot allow using the original address of a buffer, because we want buffers to be safe and we can't how address will be used */
								VM_THROW_EXCEPTION(ERROR_POINT);
							}
						}

						ret = (word)cache[val1 - 1].addr;
					}
					
				}
				VM_LEAVE_BLOCK();

			break;

			case EXP_DEREF:
				if (stage == 0) {
					VM_ENTER_BLOCK(val1);
				} else {
					if (val2 == sizeof(byte)) {
						err = safe_memory_copy(&ret_b, (byte *)ret, sizeof(byte), ADDR_INSIDE, ADDR_UNDEF, 0, 0);
						ret = (word)ret_b;
					} else if (val2 == sizeof(word)) {
						err = safe_memory_copy(&temp_value, (byte *)ret, sizeof(word), ADDR_INSIDE, ADDR_UNDEF, 0, 0);
						ret = temp_value;
					} else {
						/* we should never get here! */
						VM_THROW_EXCEPTION(ERROR_PARAM);
					}
					
					if (err < 0) {
						VM_THROW_EXCEPTION(-err);
					}
					VM_LEAVE_BLOCK();
				}
			break;
			case EXP_BUF_OFFSET:
				if (stage == 0) {
					VM_ENTER_BLOCK(val2);
				} else {

					if (state->func->code[val1].var.type == VAR_POINTER) {
						temp_value = sizeof(byte);
						temp_value2 = ret;
					} else if (state->func->code[val1].var.type == VAR_BUF) {
						if (ret >= state->func->code[val1].var.size) {
							VM_THROW_EXCEPTION(ERROR_OOB);
						}

						temp_value = sizeof(byte);
						temp_value2 = ret;
					} else {

						/* VAR_ARRAY */

						temp_value = sizeof(word);
						temp_value2 = ret * temp_value;

						/* because of the alignment we can't overflow */
						if (temp_value2 >= state->func->code[val1].var.size) {
							VM_THROW_EXCEPTION(ERROR_OOB);
						}
					}

					if (state->func->code[val1].var.type != VAR_POINTER) {

						if (val1 > state->args) {
							/* This is NOT a pointer and it's a local variable */
							ret = (temp_value == sizeof(word)) ? *(word *)(vars[val1 - 1] + temp_value2) : *(byte *)(vars[val1 - 1] + temp_value2);
							err = 0;
						} else {
							/* This is NOT a pointer and it's an argument */
							err = cache_memory_copy((byte *)vars[val1 - 1], (temp_value == sizeof(byte)) ? &ret_b : (byte *)&ret, temp_value2, temp_value, state->func->code[val1].var.size, &cache[val1 - 1], 0);
							if (temp_value == sizeof(byte)) {
								ret = ret_b;
							}
						}
					} else {
						/* This is a pointer */

						/* check if it's a dynamic memory */
						dyn = get_dyn_mem(&dyn_head, (void *)vars[val1 - 1]);
						if (NULL != dyn) {
							/* we can check boundaries */
							if (temp_value2 >= dyn->size) {
								VM_THROW_EXCEPTION(ERROR_OOB);
							}
							ret = *(byte *)(vars[val1 - 1] + temp_value2);
						} else {
							err = safe_memory_copy((temp_value == sizeof(byte)) ? &ret_b : (byte *)&ret, ((byte *)vars[val1 - 1]) + temp_value2, temp_value, ADDR_INSIDE, ADDR_UNDEF, 0, 0);
							if (temp_value == sizeof(byte)) {
								ret = ret_b;
							}
						}
					}
					if (err < 0) {
						VM_THROW_EXCEPTION(-err);
					}

					VM_LEAVE_BLOCK();
				}
			break;

			case EXP_ADD:
				if (stage == 2) {
					ret = state->val + ret;
					VM_LEAVE_BLOCK();
				}
			case EXP_SUB:
				if (stage == 2) {
					ret = state->val - ret;
					VM_LEAVE_BLOCK();
				}
			case EXP_MUL_UNSIGN:
				if (stage == 2) {
					ret = state->val * ret;
					VM_LEAVE_BLOCK();
				}
			case EXP_MUL_SIGN:
				if (stage == 2) {
					ret = (word)((sword)state->val * (sword)ret);
					VM_LEAVE_BLOCK();
				}
			case EXP_DIV_UNSIGN:
				if (stage == 2) {
					if (ret == 0) {
						VM_THROW_EXCEPTION(ERROR_DIV);
					}
					ret = state->val / ret;

					VM_LEAVE_BLOCK();
				}
			case EXP_DIV_SIGN:
				if (stage == 2) {
					if (ret == 0) {
						VM_THROW_EXCEPTION(ERROR_DIV);
					}
					ret = (word)((sword)state->val / (sword)ret);

					VM_LEAVE_BLOCK();
				}
			case EXP_AND:
				if (stage == 2) {
					ret = state->val & ret;
					VM_LEAVE_BLOCK();
				}
			case EXP_XOR:
				if (stage == 2) {
					ret = state->val ^ ret;
					VM_LEAVE_BLOCK();
				}
			case EXP_OR:
				if (stage == 2) {
					ret = state->val | ret;
					VM_LEAVE_BLOCK();
				}
			case EXP_BOOL_AND:
				if (stage == 2) {
					ret = state->val && ret;
					VM_LEAVE_BLOCK();
				}
			case EXP_BOOL_OR:
				if (stage == 2) {
					ret = state->val || ret;
					VM_LEAVE_BLOCK();
				}

			case EXP_MOD:
				if (stage == 2) {
					ret = state->val % ret;
					VM_LEAVE_BLOCK();
				}

				if (type == EXP_BOOL_OR && stage == 1 && ret) {
					VM_LEAVE_BLOCK();
				}
				if (type == EXP_BOOL_AND && stage == 1 && !ret) {
					VM_LEAVE_BLOCK();
				}
				if (stage == 0) {
					VM_ENTER_BLOCK(val1);
				} else if (stage == 1) {
					state->val = ret;
					VM_ENTER_BLOCK(val2);
				}

				/* we should never get here! */
				VM_THROW_EXCEPTION(ERROR_PARAM);
			break;
			case EXP_NOT:
				if (stage == 1) {
					ret = ~ret;
					VM_LEAVE_BLOCK();
				}
			case EXP_BOOL_NOT:
				if (stage == 1) {
					ret = !ret;
					VM_LEAVE_BLOCK();
				}
			case EXP_EXT_SIGN:
				if (stage == 1) {
					if (ret > 0xff) {
						VM_THROW_EXCEPTION(ERROR_PARAM);
					}
					ret = (word)((sword)(char)ret);
				}
				if (stage == 0) {
					VM_ENTER_BLOCK(val1);
				}

				/* we should never get here! */
				VM_THROW_EXCEPTION(ERROR_PARAM);
			break;
			case EXP_CALL_STRING:
			case EXP_CALL_PTR:
				if (stage == 0) {
					state->val = 0;
					if (type == EXP_CALL_STRING) {
						ret = 0;
						state->stage = 1;
						stage = 1;
					} else {
						VM_ENTER_BLOCK(val1);
					}
				}

				if (stage == 1) {
					/* if this is a EXP_CALL_PTR in this stage we got the address of the function in ret */
					external_function = (void *)ret;
				}

				/* in this stage we are pushing the previous argument */
				if (stage > 1) {
					if (NULL == stack_push(arg_stack, &ret)) {
						ERROR_CLEAN(-ERROR_MEM);
					}
				}

				if (state->func->code[pc + stage].expression.type == EXP_CALL_END) {
					/* this is it. now all we need is to call the right function */
					if (type == EXP_CALL_STRING) {

						if (val2 & FUNC_EXTERNAL) {
							/* an external function. trying to find it by symbol */

							external_function = find_external_function(state->func->raw + state->func->string_table[val1 - 1]);
							if (NULL == external_function) {
								DEBUG_PRINT("External \"%s\" function couldn't be found!\n", state->func->raw + state->func->string_table[val1 - 1]);
								VM_THROW_EXCEPTION(ERROR_UFUNC);
							}

							/* maybe it's not an executable symbol */
							if (!memory_check_addr_exec(external_function)) {
								VM_THROW_EXCEPTION(ERROR_POINT);
							}

							DEBUG_PRINT("Calling external function: \"%s\", PC: %lx, stage: %ld\n",
									state->func->raw + state->func->string_table[val1 - 1],
									pc, stage);

							ret = call_external_function(external_function, arg_stack, val2);

							VM_LEAVE_BLOCK();

						} else {
							/* an internal function. looking for it in our context */
							calling_function = context_find_function(state->func->cont, state->func->raw + state->func->string_table[val1 - 1]);
							if (NULL == calling_function) {
								if (NULL != GLOBAL_CONTEXT && state->func->cont != GLOBAL_CONTEXT) {
									calling_function = context_find_function(GLOBAL_CONTEXT, state->func->raw + state->func->string_table[val1 - 1]);
								}
								if (NULL == calling_function) {
									VM_THROW_EXCEPTION(ERROR_UFUNC);
								}
							}

							DEBUG_PRINT("PC: %lx, stage: %ld, Enter a VM function: %s(",
									pc, stage, state->func->raw + state->func->string_table[val1 - 1]);

							VM_CALL(calling_function);
						}

					} else {

						if (val2 & FUNC_EXTERNAL) {
							/* this is an external function using a pointer */

							/* check if this is an executable memory */
							if (!memory_check_addr_exec(external_function)) {
								VM_THROW_EXCEPTION(ERROR_POINT);
							}

							DEBUG_PRINT("Calling external function: (address:%p), PC: %lx, stage: %ld\n",
									external_function, pc, stage);


							ret = call_external_function(external_function, arg_stack, val2);
							VM_LEAVE_BLOCK();

						} else {
							/* an internal anonymous function. looking for it in our context */

							/* ok, so external_function is not really an external function, but an address of an anonymous function */
							calling_function = context_find_anonymous(state->func->cont, external_function);
							if (NULL == calling_function) {
								if (NULL != GLOBAL_CONTEXT && state->func->cont != GLOBAL_CONTEXT) {
									calling_function = context_find_anonymous(GLOBAL_CONTEXT, external_function);
								}
								if (NULL == calling_function) {
									VM_THROW_EXCEPTION(ERROR_UFUNC);
								}
							}

							DEBUG_PRINT("PC: %lx, stage: %ld, Enter a VM Anonymous function: %p(",
									pc, stage, calling_function);

							VM_CALL(calling_function);
						}
					}

				}

				/* parsing the next argument */
				VM_ENTER_BLOCK(pc + stage);

			case EXP_CALL_END:
				/* we should never get here! */
				VM_THROW_EXCEPTION(ERROR_PARAM);

			case EXP_CMP_EQ:
			case EXP_CMP_UNSIGN:
			case EXP_CMP_SIGN:

				if (stage == 0) {
					VM_ENTER_BLOCK(val1);
				} else if (stage == 1) {
					state->val = ret;
					VM_ENTER_BLOCK(val2);
				} else {
					switch (type) {
					case EXP_CMP_EQ:
						ret = (state->val == ret);
					break;
					case EXP_CMP_UNSIGN:
						ret = (state->val < ret);
					break;
					case EXP_CMP_SIGN:
						ret = ((sword)state->val) < ((sword)ret);
					break;
					default:
						/* we should never get here! */
						VM_THROW_EXCEPTION(ERROR_PARAM);
					}

					VM_LEAVE_BLOCK();
				}
			break;

			case EXP_DYN_ALLOC:
				if (stage == 0) {
					VM_ENTER_BLOCK(val1);
				} else {
					ret = (word)memory_alloc_dyn(val2 ? NULL : &dyn_head, ret);
					if ((word)NULL == ret) {
						VM_THROW_EXCEPTION(ERROR_MEM);
					}

					VM_LEAVE_BLOCK();
				}

			case EXP_ARGS:
				ret = state->args;
				VM_LEAVE_BLOCK();
			break;

			case EXP_EXP:
				if (stage == 0) {
					VM_ENTER_BLOCK(val1);
				} else {
					VM_LEAVE_BLOCK();
				}

			break;

			default:
				/* we should never get here! */
				VM_THROW_EXCEPTION(ERROR_OP);
			break;
			}
		break;
		default:
			/* we should never get here! */
			VM_THROW_EXCEPTION(ERROR_OP);
		}
	}

clean:
	if (vars) {
		memory_free(vars);
	}
	if (cache) {
		cache_clean(cache, state->func->num_maxargs);
		memory_free(cache);
	}
	stack_free(&stack);

	memory_dyn_clean(&dyn_head);

	if (err == 0) {
		return ret;
	}

	/* an error (outside the VM) occurred */
	excep->had_exception = 1;
	excep->value = -err;
	return (word)err;
}

