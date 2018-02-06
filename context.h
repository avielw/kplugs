#ifndef CONTEXT_H
#define CONTEXT_H

#include "types.h"
#include "env.h"

#ifndef __user
#define __user
#endif

typedef struct {
	byte had_exception;
	word value;
	word func;
	word pc;
} exception_t;


typedef struct {
	byte word_size	: 5;
	byte nonblock	: 1;
	byte l_endian	: 1;
	byte is_global	: 1;

	byte version_major;
	byte version_minor;
	byte error;

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

    exception_t excep;
} kplugs_command_t;

#define KPLUGS_REPLY                define_io(0, kplugs_command_t)
#define KPLUGS_LOAD                 define_io(1, kplugs_command_t)
#define KPLUGS_EXECUTE              define_io(2, kplugs_command_t)
#define KPLUGS_EXECUTE_ANONYMOUS    define_io(3, kplugs_command_t)
#define KPLUGS_UNLOAD               define_io(4, kplugs_command_t)
#define KPLUGS_UNLOAD_ANONYMOUS     define_io(5, kplugs_command_t)
#define KPLUGS_SEND_DATA            define_io(6, kplugs_command_t)
#define KPLUGS_SEND_DATA_ANONYMOUS  define_io(7, kplugs_command_t)
#define KPLUGS_RECV_DATA            define_io(8, kplugs_command_t)
#define KPLUGS_RECV_DATA_ANONYMOUS  define_io(9, kplugs_command_t)


typedef struct {
	list_head_t funcs;
	list_head_t anonym;

	spinlock_t lock;
} context_t;

/* create a new context */
int context_create(context_t **cont);
/* delete a context */
void context_free(context_t *cont);

/* lock a context */
unsigned long context_lock(context_t *cont);

/* unlock a context */
void context_unlock(context_t *cont, unsigned long flags);

/* find a function by name */
void *context_find_function(context_t *cont, byte *name);
/* find an anonymous function by address */
void *context_find_anonymous(context_t *cont, byte *ptr);

#endif
