#include "stack.h"
#include "env.h"

/* create a new stack */
int stack_alloc(stack_t *stack, word elem_size, word elem_perpage)
{
	if (!elem_size || !elem_perpage) {
		ERROR(-ERROR_PARAM);
	}

	if ((elem_size * elem_perpage) < elem_size) {
		/* overflow */
		ERROR(-ERROR_PARAM);
	}

	if (((elem_size * elem_perpage) + sizeof(byte **)*2) < elem_size) {
		/* overflow */
		ERROR(-ERROR_PARAM);
	}

	stack->buf = memory_alloc((elem_size * elem_perpage) + sizeof(byte **)*2);
	if (NULL == stack->buf) {
		ERROR(-ERROR_MEM);
	}

	*((byte **)stack->buf) = NULL;

	stack->elem_size = elem_size;
	stack->elem_perpage = elem_perpage;
	stack->tos = stack->buf + sizeof(byte **);
	stack->offset_inpage = 0;
	stack->extra = NULL;

	return 0;
}

/* delete a stack */
void stack_free(stack_t *stack)
{
	void *next = stack->tos;

	/* delete the extra page */
	if (stack->extra) {
		memory_free(stack->extra);
		stack->extra = NULL;
	}

	/* for every page in the stack... */
	do {
		/* get the next page, and free this one */
		stack->tos -= stack->offset_inpage * stack->elem_size;
		stack->tos -= sizeof(byte **);

		next = *(byte **)stack->tos;
		memory_free(stack->tos);
		stack->offset_inpage = stack->elem_perpage;
		stack->tos = next;
	} while (next != NULL);

	stack->buf = NULL;
}

/* push an element to the stack */
void *stack_push(stack_t *stack, void *elem)
{
	void *ret = NULL;
	if (stack->offset_inpage == stack->elem_perpage) {
		/* this page is full. we need to add another one */
		if (NULL == stack->extra) {
			/* we don't have a buffer cached. we need to allocate a new one */

			*(byte **)stack->tos = memory_alloc(((stack->elem_size * stack->elem_perpage) + sizeof(byte **)*2));
			if (NULL == *(byte **)stack->tos) {
				return NULL;
			}

			/* connect this new page to the last one and making it the top of stack */
			*(*(byte ***)stack->tos) = stack->tos;
			stack->tos = *(byte **)stack->tos;
		} else {
			/* we just take the extra page */
			stack->tos = stack->extra;
			stack->extra = NULL;
		}

		/* skip the pointer */
		stack->tos += sizeof(byte **);
		stack->offset_inpage = 0;
	}

	/* copy the element to the top of the stack, and moving the top */
	ret = stack->tos;
	memory_copy(stack->tos, elem, stack->elem_size);
	stack->offset_inpage++;
	stack->tos += stack->elem_size;

	return ret;
}

/* check if the stack is empty */
int stack_is_empty(stack_t * stack)
{
	return stack->tos == stack->buf + sizeof(byte **);
}

/* pop one element from the stack */
int stack_pop(stack_t *stack, void *elem)
{
	if (stack_is_empty(stack)) {
		return -ERROR_SEMPTY; /* most of the times it's not really an error */
	}

	if (stack->offset_inpage == 0) {
		/* the current page is empty. we need to move the tos back to the previous page */
		if (stack->extra) {
			/* we already have an extra. we free it to make a room for the new one */
			memory_free(stack->extra);
		}

		/* skip the pointer */
		stack->extra = stack->tos - sizeof(byte **);
		stack->offset_inpage = stack->elem_perpage;
		stack->tos = *(byte **)stack->extra;
	}

	/* copy the element from the top of stack, and moving the top */
	if (elem != NULL) {
		memory_copy(elem, stack->tos - stack->elem_size, stack->elem_size);
	}
	stack->offset_inpage--;
	stack->tos -= stack->elem_size;

	return 0;
}

/* return one element from the stack without taking it out */
void *stack_peek(stack_t *stack)
{
	byte *tos = stack->tos;

	if (stack_is_empty(stack)) {
		return NULL;
	}

	if (stack->offset_inpage == 0) {
		tos = *(byte **)(stack->tos - sizeof(byte **));
	}

	return tos - stack->elem_size;
}
