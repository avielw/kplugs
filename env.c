#include "config.h"
#include "types.h"
#include "memory.h"

#include <stdarg.h>

#ifdef __KERNEL__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#ifdef USE_KALLSYMS
#include <linux/kallsyms.h>
#endif

MODULE_LICENSE("GPL");

#else

#include <stdio.h>
#include <malloc.h>
#include <string.h>

/* for dlsym() */
#define	__USE_GNU
#include <dlfcn.h>

#endif

#include "env.h"
#include "memory.h"

/* allocate memory */
void *memory_alloc(word size)
{
#ifdef __KERNEL__
	/* we don't know in which context we run the we want the allocation to be atomic */
	return kmalloc(size, GFP_ATOMIC);
#else
	return malloc(size);
#endif
}

/* free memory */
void memory_free(void *mem)
{
#ifdef __KERNEL__
	kfree(mem);
#else
	free(mem);
#endif
}

/* copy data from inside memory to inside memory */
void *memory_copy(void *dst, void *src, word len)
{
	return memcpy(dst, src, len);
}


/* copy data from outside memory to inside memory */
int memory_copy_from_outside(void *dst, void *src, word len)
{
#ifdef __KERNEL__
	return safe_memory_copy(dst, src, len, ADDR_INSIDE, ADDR_OUTSIDE, 0, 0);
#else
	memcpy(dst, src, len);
	return 0;
#endif
}


/* copy data from inside memory to outside memory */
int memory_copy_to_outside(void *dst, void *src, word len)
{
#ifdef __KERNEL__
	return safe_memory_copy(dst, src, len, ADDR_OUTSIDE, ADDR_INSIDE, 0, 0);
#else
	memcpy(dst, src, len);
	return 0;
#endif
}


/* set the value of an inside memory */
void *memory_set(void *str, int ch, word num)
{
	return memset(str, ch, num);
}


/* compare two strings */
int string_compare(const char *s1, const char *s2)
{
	return strcmp(s1, s2);
}


/* copy a string to a buffer */
char *string_copy(char *s1, const char *s2)
{
	return strcpy(s1, s2);
}


/* get a string's length */
int string_len(const char *s)
{
	return strlen(s);
}

/* find an external function by its name */
void *find_external_function(const byte *name)
{
#ifdef __KERNEL__
#ifdef USE_KALLSYMS
	unsigned long ret = kallsyms_lookup_name(name);
	return (ret == 0 ? NULL : (void *)ret);
#else
	const struct kernel_symbol *sym;

	preempt_disable();
	sym = find_symbol(name, NULL, NULL, 1, 0);
	preempt_enable();
	if (sym != NULL) {
		return (void *)(sym->value);
	}
	return NULL;
#endif

#else
	return dlsym(RTLD_NEXT, (const char *)name);
#endif
}

#ifndef __KERNEL__

/* the user mode version is just for testing, AND IS NOT THREAD SAFE */

inline int atomic_dec_and_test(atomic_t *atom)
{
	return (--(*atom)) == 0;
}

#endif
