#ifndef STACK_H
#define STACK_H

#include "types.h"

typedef struct {
	word elem_size;			/* the size of an element */
	word elem_perpage;		/* the number of elements per page in the stack */

	word offset_inpage;		/* the offset (in elements) of the top of stack in the current page */
	byte *tos;				/* points to the top of the stack */
	byte *buf;				/* points to the bottom of the stack */
	byte *extra;			/* points to a cached page that will be used in the next stack extension */
} stack_t;


/* create a new stack */
int stack_alloc(stack_t *stack, word elem_size, word elem_perpage);

/* delete a stack */
void stack_free(stack_t *stack);

/* push an element to the stack */
void *stack_push(stack_t *stack, void *elem);

/* pop one element from the stack */
int stack_pop(stack_t *stack, void *elem);

/* return one element from the stack without taking it out */
void *stack_peek(stack_t *stack);

/* check if the stack is empty */
int stack_is_empty(stack_t * stack);

#endif
