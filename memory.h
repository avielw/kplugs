#ifndef MEMORY_H
#define MEMORY_H

#include "types.h"

struct queue_head;

/* memory types */
typedef enum {
	ADDR_UNDEF,
	ADDR_OUTSIDE,
	ADDR_INSIDE,
} address_type_t;

/* this is our simple heap for executable and writable pages */
typedef struct heap_s {
	struct heap_s *next;

	word elem_size;
	word allocated;
	word num_elem;
	byte *first_elem;
} heap_t;


typedef struct dyn_mem_s {
	struct dyn_mem_s *next;
	struct dyn_mem_s *head;
	word size;

	byte data[1];
} dyn_mem_t;


/* copy memory from safely from any type of memory to any type of memory (optional - from different processes) */
int safe_memory_copy(void *dst, const void *src, word len, int dst_hint, int src_hint, word dst_pid, word src_pid);

/* allocate executable and writable memory */
void *memory_alloc_exec(word size);
/* free an executable buffer */
void memory_free_exec(void *mem);


/* start memory - makes sure all the structures are initialized */
void memory_start(void);
/* stop memory, and delete any buffer that wasn't deleted */
void memory_stop(void);

/* initialize a dynamic memory head */
void memory_dyn_init(dyn_mem_t *head);
/* free an entire dynamic memory struct */
void memory_dyn_clean(dyn_mem_t *head);
/* allocate a dynamic memory */
void *memory_alloc_dyn(dyn_mem_t *head, word size);
/* free a dynamic memory */
int memory_free_dyn(dyn_mem_t *head, void *ptr);
/* checks if a pointer is a dynamic memory */
dyn_mem_t *get_dyn_mem(dyn_mem_t *head, void *ptr);
/* transfer a dynamic memory from one head to another */
int transfer_dyn_mem(dyn_mem_t *head, dyn_mem_t *dyn);

/* callback for the queue struct */
void dyn_free_callback(void *data);
/* get a buffer from user */
int recv_data_from_other(struct queue_head *queue, dyn_mem_t *head, dyn_mem_t **dyn, int nonblock);
/* send a buffer to user */
int send_data_to_other(struct queue_head *queue, dyn_mem_t *dyn, int nonblock);

/* check memory permissions */
int memory_check_addr_perm(const byte *addr, word *size, int write, byte *read_only);

/* check if a memory is executable */
int memory_check_addr_exec(const byte *addr);

/* map an outside memory to an inside memory */
int memory_map(const byte *addr, word *size, void **map, byte **new_addr, int write);

/* unmap an outside memory */
void memory_unmap(byte *addr);

#endif
