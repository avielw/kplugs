#include "context.h"
#include "function.h"
#include "env.h"
#include "vm.h"
#include "types.h"
#include "queue.h"

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
	spin_lock_init(&(*cont)->lock);

	return 0;
}

/* lock a context */
unsigned long context_lock(context_t *cont)
{
	unsigned long flags;

	spin_lock_irqsave(&cont->lock, flags);

	return flags;
}

/* unlock a context */
void context_unlock(context_t *cont, unsigned long flags)
{
	spin_unlock_irqrestore(&cont->lock, flags);
}

/* add a function to a context */
int context_add_function(context_t *cont, function_t *func)
{
	function_t *check_func = NULL;
	unsigned long flags;
	int err = 0;

	flags = context_lock(cont);

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
	context_unlock(cont, flags);
	return err;
}

/* remove and delete a function from the context */
void context_free_function(function_t *func)
{
	context_t *cont = func->cont;
	unsigned long flags;

	flags = context_lock(cont);

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

	queue_kill(&func->to_user);
	queue_kill(&func->to_kernel);

	function_put(func);

clean:
	context_unlock(cont, flags);
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
	unsigned long flags;

	flags = context_lock(cont);

	func = LIST_TO_STRUCT(function_t, list, cont->funcs.next);
	while (func != NULL) {
		if (!string_compare(func->name, (char *)name)) {
			function_get(func);
			goto clean;
		}
		func = LIST_TO_STRUCT(function_t, list, func->list.next);
	}

clean:
	context_unlock(cont, flags);
	return func;
}

/* find an anonymous function by address */
void *context_find_anonymous(context_t *cont, byte *ptr)
{
	unsigned long flags;
	function_t *func;

	flags = context_lock(cont);

	func = LIST_TO_STRUCT(function_t, list, cont->anonym.next);
	while (func != NULL) {
		if (func->func_code == ptr) {
			function_get(func);
			goto clean;
		}
		func = LIST_TO_STRUCT(function_t, list, func->list.next);
	}

clean:
	context_unlock(cont, flags);
	return func;
}

