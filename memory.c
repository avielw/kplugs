#include "types.h"

#ifdef __KERNEL__

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/mm_types.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

#include "env.h"
#include "memory.h"

/* check the permissions of a address and return its type - */
static int memory_check_addr_perm_task(const void *addr, word *size, int write, byte *read_only, byte *executable, struct task_struct *task)
{
	struct vm_area_struct *vma;
	word start = ROUNDDOWN((word)addr, PAGE_SIZE);
	word end = ROUNDUP((word)addr + *size, PAGE_SIZE);
	word total_size = 0;
	byte local_read_only = 0;
	byte local_executable = 0;
	int ret = ADDR_UNDEF;
	int atomic;
#ifdef HAS_LOOKUP_ADDRESS
	pte_t *pte;
	unsigned int level;
#endif

	if (NULL == read_only) {
		read_only = &local_read_only;
	}

	if (NULL == executable) {
		executable = &local_executable;
	}

	*read_only = 0;
	*executable = 0;

	atomic = in_atomic();

	if (!atomic) {
		down_read(&task->mm->mmap_sem);
	}

	while (start < end) {
		if (task && task->mm) {
			/* check if it's a user address */
			vma = find_vma(task->mm, start);
			if (vma && vma->vm_start <= start) {
				if (ret != ADDR_UNDEF && ret != ADDR_OUTSIDE) {
					goto end;
				}

				if (!(vma->vm_flags & VM_READ)) {
					goto end;
				}

				if (!(vma->vm_flags & VM_WRITE)) {
					if (write) {
						/* no more writable bytes */
						goto end;

					} else if (ret != ADDR_UNDEF && !(*read_only)) {
						/* the permissions has changed. this is where we stop the buffer */
						goto end;
					}

					*read_only = 1;
				}

				start = vma->vm_end;
				total_size = start - (word)addr;
				ret = ADDR_OUTSIDE;
				continue;
			}
		}

		/* check if it's a kernel virtual address */

#ifdef HAS_LOOKUP_ADDRESS
		pte = lookup_address((unsigned long)addr, &level);
		if (NULL == pte) {
			goto end;
		}

		if (ret == ADDR_UNDEF) {
			*executable = pte_exec(*pte);
		}

		if (pte_present(*pte)) {
			if (ret != ADDR_UNDEF && ret != ADDR_INSIDE) {
				goto end;
			}

			if (!pte_write(*pte)) {
				if (write) {
					/* no more writable bytes */
					goto end;

				} else if (ret != ADDR_UNDEF && !(*read_only)) {
					/* the permissions has changed. this is where we stop the buffer */
					goto end;
				}

				*read_only = 1;
			}

			start += PAGE_SIZE;
			total_size = start - (word)addr;
			ret = ADDR_INSIDE;
			continue;
		}
		goto end;
#else
		if (ret != ADDR_UNDEF && ret != ADDR_INSIDE) {
			goto end;
		}

		if (	start >= PAGE_OFFSET ||
			(start >= MODULES_VADDR && start < MODULES_END) ||
			(start >= VMALLOC_START && start < VMALLOC_END)) {
			/* this is not totally safe. but it's enough for now. */
			*executable = 1;
			start += PAGE_SIZE;
			total_size = start - (word)addr;
			ret = ADDR_INSIDE;
			continue;
		}
		goto end;
#endif
	}

end:
	if (!atomic) {
		up_read(&task->mm->mmap_sem);
	}
	if (total_size) {
		if (total_size < *size) {
			*size = total_size;
		}
		return ret;
	} else {
		return ADDR_UNDEF;
	}
}


/* map an outside memory to an inside memory by task */
static int memory_map_task(const byte *addr, word *size, void **map, byte **new_addr, int write, struct task_struct *task)
{
	word start;
	word offset;
	word end_offset;
	word npages;
	struct page **pages = NULL;
	int ret;

	if (*size == 0) {
		return 0;
	}

	start = ROUNDDOWN((word)addr, PAGE_SIZE);
	offset = ((word)addr) & (PAGE_SIZE - 1);
	end_offset = (((word)addr) + *size) & (PAGE_SIZE - 1);

	npages = ROUNDUP((word)addr + *size, PAGE_SIZE) - start;
	npages /= PAGE_SIZE;

	if (npages == 0) {
		/* integer overflow when rounding up */
		ERROR(-ERROR_MEM);
	}

	pages = memory_alloc(npages * sizeof(struct page *));
	if (NULL == pages) {
		ERROR(-ERROR_MEM);
	}

	ret = get_user_pages_remote(task, task->mm, start, npages, write, 0, pages, NULL);
	if (ret <= 0) {
		memory_free(pages);
		ERROR(-ERROR_POINT);
	}

	if (ret != npages) {
		BUG_ON(ret > npages);

		*size -= ((npages - ret) - 1) * PAGE_SIZE;
		*size -= (end_offset ? end_offset : PAGE_SIZE);
		npages = ret;
	}

	BUG_ON((int)*size < 0);

#ifndef PAGE_KERNEL_RO
	*map = vmap(pages, npages, 0, PAGE_KERNEL);
#else
	*map = vmap(pages, npages, 0, write ? PAGE_KERNEL : PAGE_KERNEL_RO);
#endif
	memory_free(pages);
	if (NULL == *map) {
		ERROR(-ERROR_POINT);
	}

	*new_addr = (byte *)(((word)(*map)) + offset);
	return 0;
}

/* copy memory from safely from any type of memory to any type of memory (optional - from different processes) */
int safe_memory_copy(void *dst, const void *src, word len, int dst_hint, int src_hint, word dst_pid, word src_pid)
{
	word new_len = len;
	int dst_type, src_type;
	void *dst_map = NULL;
	void *src_map = NULL;
	struct task_struct *dst_task = current;
	struct task_struct *src_task = current;
	struct pid *pid_struct;
	int err = 0;

	if (!len) {
		return 0;
	}

	/* load the correct task structs: */

	if (dst_pid || src_pid) {
		rcu_read_lock();
	}

	if (dst_pid) {
		pid_struct = find_vpid(dst_pid);
		 if (NULL == pid_struct) {
			ERROR_CLEAN(-ERROR_PARAM);
		}
		dst_task = pid_task(pid_struct, PIDTYPE_PID);
	}

	if (NULL == dst_task) {
		ERROR_CLEAN(-ERROR_PARAM);
	}

	if (src_pid) {
		pid_struct = find_vpid(src_pid);
		 if (NULL == pid_struct) {
			ERROR_CLEAN(-ERROR_PARAM);
		}
		src_task = pid_task(pid_struct, PIDTYPE_PID);
	}

	if (NULL == src_task) {
		ERROR_CLEAN(-ERROR_PARAM);
	}


	/* if we don't know where this addresses came from, find out: */

	if (dst_hint != ADDR_UNDEF) {
		dst_type = dst_hint;
	} else {
		dst_type = memory_check_addr_perm_task(dst, &new_len, 1, NULL, NULL, dst_task);
		if (dst_type == ADDR_UNDEF || new_len != len) {
			ERROR_CLEAN(-ERROR_POINT);
		}
	}

	if (src_hint != ADDR_UNDEF) {
		src_type = src_hint;
	} else {
		src_type = memory_check_addr_perm_task(src, &new_len, 0, NULL, NULL, src_task);
		if (src_type == ADDR_UNDEF || new_len != len) {
			ERROR_CLEAN(-ERROR_POINT);
		}
	}

	/* map user pages if we need to: */

	/* IMPORTANT:
	 * if you need to map user pages it cannot be atomic!
	 * so if you are using a page from user space you should not
	 * use this function in an atomic only context.
	 */
	if (dst_type == ADDR_OUTSIDE) {
		err = memory_map_task(dst, &new_len, &dst_map, (byte **)&dst, 1, dst_task);
		if (err < 0 || new_len != len) {
			goto clean;	
		}
	}

	if (src_type == ADDR_OUTSIDE) {
		err = memory_map_task(src, &new_len, &src_map, (byte **)&src, 0, src_task);
		if (err < 0 || new_len != len) {
			goto clean;	
		}
	}

	memory_copy(dst, src, len);
	err = 0;
clean:
	if (dst_pid || src_pid) {
		rcu_read_unlock();
	}

	if (dst_map) {
		memory_unmap(dst_map);
	}
	if (src_map) {
		memory_unmap(src_map);
	}

	return err;
}

EXPORT_SYMBOL(safe_memory_copy);

/* check memory permissions */
int memory_check_addr_perm(const byte *addr, word *size, int write, byte *read_only)
{
	return memory_check_addr_perm_task(addr, size, write, read_only, NULL, current);
}


/* check if a memory is executable */
int memory_check_addr_exec(const byte *addr)
{
	byte exec = 0;
	word size = 1;

	/* we don't have to check the return value, because we only need to check if the memory is executable */
	memory_check_addr_perm_task(addr, &size, 0, NULL, &exec, current);

	return exec;
}

/* map an outside memory to an inside memory */
int memory_map(const byte *addr, word *len, void **map, byte **new_addr, int write)
{
	return memory_map_task(addr, len, map, new_addr, write, current);
}

/* unmap an outside memory */
void memory_unmap(byte *addr)
{
	vunmap(addr);
}

#else

#include "env.h"
#include "memory.h"

#include <sys/mman.h>

/* copy memory from safely from any type of memory to any type of memory (optional - from different processes) */
int safe_memory_copy(void *dst, void *src, word len, int dst_hint, int src_hint, word dst_pid, word src_pid)
{
	memory_copy(dst, src, len);
	return 0;
}

/* check memory permissions */
int memory_check_addr_perm(const byte *addr, word *size, int write, byte *read_only)
{
	if (NULL != read_only) {
		*read_only = 0;
	}
	return ADDR_INSIDE;
}

/* check if a memory is executable */
int memory_check_addr_exec(const byte *addr)
{
	/* we don't really check anything if there is no outside memory */
	return 1;
}

/* map an outside memory to an inside memory */
int memory_map(const byte *addr, word *size, void **map, byte **new_addr, int write)
{
	/* all the memories are inside memory so this should never be called */
	*new_addr = addr;
	*map = NULL;
	return 0;
}

/* unmap an outside memory */
void memory_unmap(byte *addr)
{
	/* there is no outside memory */
	return;
}


#endif

dyn_mem_t dyn_global_head;

/* initialize a dynamic memory head */
void memory_dyn_init(dyn_mem_t *head)
{
	head->next = NULL;
}

void memory_dyn_clean(dyn_mem_t *head)
{
	dyn_mem_t *dyn = head->next;
	dyn_mem_t *next;
	while (NULL != dyn) {
		next = dyn->next;
		memory_free(dyn);
		dyn = next;
	}
}

/* allocate a dynamic memory */
void *memory_alloc_dyn(dyn_mem_t *head, word size)
{
	dyn_mem_t *dyn;

	if (size + sizeof(dyn_mem_t) < sizeof(dyn_mem_t)) {
		return NULL;
	}

	dyn = memory_alloc(sizeof(dyn_mem_t) + size);
	if (NULL == dyn) {
		return NULL;
	}

	if (head == NULL) {
		head = &dyn_global_head;
	}

	dyn->size = size;
	dyn->next = head->next;
	head->next = dyn;

	return (void *)&dyn->data;
}

/* free a dynamic memory */
int memory_free_dyn(dyn_mem_t *head, void *ptr)
{
	dyn_mem_t *dyn;
	dyn_mem_t *prev;

	if (head == NULL) {
		head = &dyn_global_head;
	}

again:
	prev = head;
	dyn = prev->next;
	while (NULL != dyn) {
		if (&dyn->data == ptr) {
			prev->next = dyn->next;
			memory_free(dyn);
			return 0;
		}
		prev = dyn;
		dyn = dyn->next;
	}

	if (head != &dyn_global_head) {
		head = &dyn_global_head;
		goto again;
	}
	return -ERROR_NODYM;
}

/* checks if a pointer is a dynamic memory */
dyn_mem_t *get_dyn_mem(dyn_mem_t *head, void *ptr)
{
	dyn_mem_t *dyn;

	if (head == NULL) {
		head = &dyn_global_head;
	}

again:
	dyn = head->next;
	while (NULL != dyn) {
		if (&dyn->data == ptr) {
			return dyn;
		}
		dyn = dyn->next;
	}

	if (head != &dyn_global_head) {
		head = &dyn_global_head;
		goto again;
	}
	return NULL;
}


/* This is the code of a simple heap. */
/* we need it because in the kernel you cannot use the allocator (cache) to allocate executable memory, and we want to allocate executable buffers */

heap_t *heaps;

/* allocate executable and writable memory */
void *memory_alloc_exec(word size)
{
	heap_t *found_heap = heaps;
	heap_t *new_heap = NULL;
	void *ret = NULL;

	size = ROUNDUP(size, sizeof(word));
	if (size < sizeof(word)) {
		return NULL;
	}

	if (size >= ((PAGE_SIZE - sizeof(heap_t)) / 2)) {
		/* big buffers receive a whole page */
#ifdef __KERNEL__
		ret = __vmalloc(size, GFP_ATOMIC, PAGE_KERNEL_EXEC);
		if (NULL == ret) {
#else
		ret = mmap(NULL, ROUNDUP(size, PAGE_SIZE), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if ((sword)ret == -1) {
#endif
			return NULL;
		}
		return ret;
	}

	/* find the heap with elements big enough for us */
	while (NULL != found_heap) {
		if (found_heap->elem_size >= size && found_heap->allocated < found_heap->num_elem) {
			break;
		}
		found_heap = found_heap->next;
	}

	if (NULL == found_heap) {
		/* we need to create a new heap */
#ifdef __KERNEL__
		new_heap = __vmalloc(PAGE_SIZE, GFP_ATOMIC, PAGE_KERNEL_EXEC);
		if (NULL == new_heap) {
#else
		new_heap = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if ((sword)new_heap == -1) {
#endif
			return NULL;
		}

		memory_set(new_heap, 0, PAGE_SIZE);
		new_heap->next = NULL;
		new_heap->elem_size = size;
		new_heap->allocated = 1;
		new_heap->num_elem = (PAGE_SIZE - sizeof(heap_t)) / size;
		new_heap->first_elem = (byte *)new_heap + sizeof(heap_t) + size;
		if (heaps == NULL) {
			heaps = new_heap;
		} else {
			found_heap = heaps;
			while (NULL != found_heap->next) {
				found_heap = found_heap->next;
			}
			found_heap->next = new_heap;
		}
		/* return the first element */
		return (void *)((byte *)new_heap + sizeof(heap_t));
	} else {
		/* we found a heap */
		found_heap->allocated++;
		ret = found_heap->first_elem;
		if (found_heap->allocated < found_heap->num_elem) {
			/* update the next element to be returned */
			if (*(byte **)(found_heap->first_elem) == NULL) {
				found_heap->first_elem += found_heap->elem_size;
			} else {
				found_heap->first_elem = *(byte **)(found_heap->first_elem);
			}
		}
		return ret;
	}
	/* we should never get here */
	return NULL;
}

/* free an executable buffer */
void memory_free_exec(void *mem)
{
	heap_t *found_heap = (heap_t *)(ROUNDDOWN((word)(mem), PAGE_SIZE));
	heap_t *del_heap = NULL;

	if (((word)mem & (PAGE_SIZE - 1)) == 0) {
		/* if the buffer is page aligned, it is a large buffer */
#ifdef __KERNEL__
		vfree(mem);
#else
		munmap(mem, PAGE_SIZE);
#endif
		return;
	}

	found_heap->allocated--;
	if (0 == found_heap->allocated) {
		/* the heap is now empty. we free it: */
		if (heaps == found_heap) {
			heaps = found_heap->next;
		} else {
			del_heap = heaps;
			while (del_heap->next != found_heap) {
				del_heap = del_heap->next;
			}
			del_heap->next = found_heap->next;
		}
#ifdef __KERNEL__
		vfree(found_heap);
#else
		munmap(found_heap, PAGE_SIZE);
#endif
	} else {
		/* the heap still have buffers in use. put this buffer in the list */
		*(byte **)mem = found_heap->first_elem;
		found_heap->first_elem = mem;
	}
}


/* start memory - makes sure all the structures are initialized */
void memory_start(void)
{
	heaps = NULL;
	memory_dyn_init(&dyn_global_head);
}

/* stop memory, and delete any buffer that wasn't deleted */
void memory_stop(void)
{
	if (NULL != heaps) {
		/* we should never get here! */
		output_string("Warning: a buffer was not freed from the heap!\n");

		/* we won't delete anything because we don't know how this situation is even possible, and we want to avoid a used-after-free */
	}

	memory_dyn_clean(&dyn_global_head);
}
