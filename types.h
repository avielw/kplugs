#ifndef TYPES_H
#define TYPES_H

typedef enum {
	ERROR_OK,
	ERROR_MEM,		/* no more memory */
	ERROR_RECUR,	/* recursion to deep */
	ERROR_OP,		/* wrong operation */
	ERROR_VAR,		/* wrong variable */
	ERROR_PARAM,	/* wrong parameter */
	ERROR_REFER,	/* this operation is been used more the once */
	ERROR_FLOW,		/* a flow block was not terminated */
	ERROR_EXPLO,	/* some of the code was not explored */
	ERROR_NAME,		/* bad function name */
	ERROR_FEXIST,	/* function already exists */
	ERROR_SEMPTY,	/* the stack is empty */
	ERROR_POINT,	/* bad pointer */
	ERROR_OOB,		/* (out of bounds) access outside of a buffer's limit */
	ERROR_DIV,		/* divide by zero */
	ERROR_UFUNC,	/* unknown function */
	ERROR_ARGS,		/* bad number of arguments */
	ERROR_ARCH,		/* wrong architecture */
	ERROR_VERSION,	/* unsupported version */
	ERROR_NODYM,	/* not a dynamic memory */
	ERROR_INTER,	/* operation was interrupted */
} error_t;

typedef struct list_head_s {
	struct list_head_s *next;
	struct list_head_s *prev;
} list_head_t;

typedef unsigned long word;
typedef signed long sword;
typedef unsigned char byte;

#endif
