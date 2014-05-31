#include "context.h"
#include "function.h"
#include "env.h"
#include "vm.h"
#include "types.h"

/* create a new context */
int context_create(context_t **cont)
{
	*cont = memory_alloc(sizeof(context_t));

	if (NULL == *cont) {
		ERROR(-ERROR_MEM);
	}

	(*cont)->funcs.next = NULL;
	(*cont)->funcs.prev = NULL;
	(*cont)->anonym.next = NULL;
	(*cont)->anonym.prev = NULL;
	(*cont)->has_answer = 0;
	(*cont)->last_exception.had_exception = 0;
	spin_lock_init(&(*cont)->lock);

	return 0;
}

/* lock a context */
void context_lock(context_t *cont)
{
	spin_lock(&cont->lock);
}

/* unlock a context */
void context_unlock(context_t *cont)
{
	spin_unlock(&cont->lock);
}

/* add a function to a context */
int context_add_function(context_t *cont, function_t *func)
{
	function_t *check_func = NULL;
	int err = 0;

	context_lock(cont);

	if (func->name != NULL) {
		/* this is a function with a name */
		check_func = LIST_TO_STRUCT(function_t, list, cont->funcs.next);

		/* check that we don't have this function's name already */
		while (check_func != NULL) {
			if (!string_compare(check_func->name, func->name)) {
				ERROR_CLEAN(-ERROR_FEXIST);
			}
			check_func = LIST_TO_STRUCT(function_t, list, check_func->list.next);
		}

		/* add the function to the funcs list */
		func->list.next = cont->funcs.next;
		func->list.prev = &cont->funcs;

		if (cont->funcs.next != NULL) {
			cont->funcs.next->prev = &func->list;
		}
		cont->funcs.next = &func->list;

	} else {
		/* this is a anonymous function */

		/* add the function to the anonym list */
		func->list.next = cont->anonym.next;
		func->list.prev = &cont->anonym;

		if (cont->anonym.next != NULL) {
			cont->anonym.next->prev = &func->list;
		}
		cont->anonym.next = &func->list;
	}

	func->cont = cont;

clean:
	context_unlock(cont);
	return err;
}

/* remove and delete a function from the context */
void context_free_function(function_t *func)
{
	context_t *cont = func->cont;

	context_lock(cont);

	if (NULL == func->list.prev && NULL == func->list.next) {
		/* This is a race condition! The function was already removed from the context... */
		goto clean;
	}

	func->list.prev->next = func->list.next;
	if (func->list.next != NULL) {
		func->list.next->prev = func->list.prev;
	}

	func->list.prev = NULL;
	func->list.next = NULL;

	function_put(func);

clean:
	context_unlock(cont);
}

/* delete a context */
void context_free(context_t *cont)
{
	/* we don't need to lock because this is called only when we free the context anyway */

	while (cont->funcs.next != NULL) {
		context_free_function(LIST_TO_STRUCT(function_t, list, cont->funcs.next));
	}
	while (cont->anonym.next != NULL) {
		context_free_function(LIST_TO_STRUCT(function_t, list, cont->anonym.next));
	}

	memory_free(cont);
}

/* find a function by name */
void *context_find_function(context_t *cont, byte *name)
{
	function_t *func;
	
	context_lock(cont);

	func = LIST_TO_STRUCT(function_t, list, cont->funcs.next);
	while (func != NULL) {
		if (!string_compare(func->name, (char *)name)) {
			function_get(func);
			goto clean;
		}
		func = LIST_TO_STRUCT(function_t, list, func->list.next);
	}

clean:
	context_unlock(cont);
	return func;
}

/* find an anonymous function by address */
void *context_find_anonymous(context_t *cont, byte *ptr)
{
	function_t *func;

	context_lock(cont);

	func = LIST_TO_STRUCT(function_t, list, cont->anonym.next);
	while (func != NULL) {
		if (func->func_code == ptr) {
			function_get(func);
			goto clean;
		}
		func = LIST_TO_STRUCT(function_t, list, func->list.next);
	}

clean:
	context_unlock(cont);
	return func;
}

/* copy the reply back to the user */
int context_get_reply(context_t *cont, char *buf, word length)
{
	word copy;

	context_lock(cont);

	/* return an answer if there is one */
	if (cont->has_answer) {
		copy = (length > sizeof(kplugs_command_t)) ? sizeof(kplugs_command_t) : length;
		memory_copy(buf, &cont->cmd, copy);
		cont->has_answer = 0;
	} else {
		copy = 0;
	}

	context_unlock(cont);

	return (int)copy;
}

/* copy the last exception to inside or outside memory */
int context_get_last_exception(context_t *cont, exception_t *excep)
{
	int err;

	context_lock(cont);

	if (!cont->last_exception.had_exception) {
		ERROR_CLEAN(-ERROR_PARAM);
	}

	err = safe_memory_copy(excep, &cont->last_exception, sizeof(exception_t), ADDR_UNDEF, ADDR_INSIDE, 0, 0);

	cont->last_exception.had_exception = 0;

clean:
	context_unlock(cont);
	return err;
}

/* create a reply */
void context_create_reply(context_t *cont, word val, exception_t *excep)
{
	context_lock(cont);

	if (NULL != excep) {
		memory_copy(&cont->last_exception, excep, sizeof(exception_t));
	}

	memory_set(&cont->cmd, 0, sizeof(kplugs_command_t));
	cont->cmd.val1 = val;
	cont->cmd.type = KPLUGS_REPLY;
	cont->has_answer = 1;

	context_unlock(cont);
}
