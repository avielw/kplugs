#ifndef ENV_H
#define ENV_H


#include "types.h"
#include "config.h"

#include <stdarg.h>

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((word) &((TYPE *)0)->MEMBER)
#endif

#define LIST_TO_STRUCT(TYPE, MEMBER, LIST) ((TYPE *)(((byte *)LIST) - offsetof(TYPE, MEMBER)))

/* allocate memory */
void *memory_alloc(word size);

/* free memory */
void memory_free(void *mem);

/* copy data from inside memory to inside memory */
void *memory_copy(void *dst, const void *src, word len);

/* copy data from outside memory to inside memory */
int memory_copy_from_outside(void *dst, const void *src, word len);

/* copy data from inside memory to outside memory */
int memory_copy_to_outside(void *dst, const void *src, word len);

/* set the value of an inside memory */
void *memory_set(void *str, int ch, word num);

/* compare two strings */
int string_compare(const char *s1, const char *s2);

/* copy a string to a buffer */
char *string_copy(char *s1, const char *s2);

/* get a string's length */
int string_len(const char *s);

/* find an external function by its name */
void *find_external_function(const byte *name);


/* functions to print to a standard output */
#ifdef __KERNEL__

#include <linux/kernel.h>
#include <linux/spinlock.h>

#define output_string(...) printk(__VA_ARGS__)

#else

#include <stdio.h>

#define output_string(...) printf(__VA_ARGS__)


/* the user mode version is just for testing, AND IS NOT THREAD SAFE: */

typedef word spinlock_t;
typedef word atomic_t;

#define spin_lock_init(lock)
#define spin_lock(lock)
#define spin_unlock(lock)

#define atomic_set(atom, val) 		do { (*(atom))=val; } while (0)
#define atomic_inc(atom)			do { ++(*(atom)); } while (0)
inline int atomic_dec_and_test(atomic_t *atom);

#endif

#include "memory.h"


#ifndef PAGE_SIZE
#define PAGE_SIZE (0x1000)
#endif

#ifndef BITS_PER_BYTE
#define BITS_PER_BYTE (8)
#endif

/* works only with elements which there size is a power of two! */
#define ROUNDUP(num, elem) (((num) + (elem) - 1) & (~((elem) - 1)))
#define ROUNDDOWN(num, elem) ((num) & (~((elem) - 1)))

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif

#define ERROR_PRINT(n) DEBUG_PRINT("ERROR %d: in line %d of file \"%s\"\n", n, __LINE__, __FILE__)

#define ERROR(n) if (n) { \
	ERROR_PRINT(n); \
	return n; \
} else return 0

#define ERROR_CLEAN(n) if (n) { \
	ERROR_PRINT(n); \
} err = n; goto clean

#define CHECK_ERROR(err) do { \
	if ((err) < 0) { goto clean; } \
} while (0)


#endif
