#ifndef CONTEXT_H
#define CONTEXT_H

#include "types.h"
#include "env.h"

#ifndef __user
#define __user
#endif

typedef enum {
	KPLUGS_REPLY,
	KPLUGS_LOAD,
	KPLUGS_EXECUTE,
	KPLUGS_EXECUTE_ANONYMOUS,
	KPLUGS_UNLOAD,
	KPLUGS_UNLOAD_ANONYMOUS,
	KPLUGS_GET_LAST_EXCEPTION,
} kplugs_command_types_t;


typedef struct {
	byte word_size	: 7;
	byte l_endian	: 1;

	byte version_major;
	byte version_minor;

	byte type 		: 7;
	byte is_global	: 1;
	word len1;
	word len2;

	union {
		byte __user *uptr1;
		byte *ptr1;
		word val1;
	};
	union {
		byte __user *uptr2;
		byte *ptr2;
		word val2;
	};
} kplugs_command_t;


typedef struct {
	byte had_exception;
	word value;
	word func;
	word pc;
} exception_t;

typedef struct {
	list_head_t funcs;
	list_head_t anonym;

	spinlock_t lock;

	byte has_answer;
	kplugs_command_t cmd;
	exception_t last_exception;
} context_t;

/* create a new context */
int context_create(context_t **cont);
/* delete a context */
void context_free(context_t *cont);

/* lock a context */
void context_lock(context_t *cont);

/* unlock a context */
void context_unlock(context_t *cont);

/* find a function by name */
void *context_find_function(context_t *cont, byte *name);
/* find an anonymous function by address */
void *context_find_anonymous(context_t *cont, byte *ptr);

/* copy the last exception to inside or outside memory */
int context_get_last_exception(context_t *cont, exception_t *excep);

/* copy the reply back to the user */
int context_get_reply(context_t *cont, char *buf, word length);

/* create a reply */
void context_create_reply(context_t *cont, word val, exception_t *excep);

#endif
