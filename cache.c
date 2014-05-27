#include "config.h"
#include "env.h"
#include "types.h"

#include "cache.h"

/* map a memory to a cache */
int cache_memory_map(byte *addr, word size, arg_cache_t *cache, int write)
{
	int ret;

	cache->size = size;

	/* check the permissions */
	ret = memory_check_addr_perm(addr, &cache->size, write, &cache->read_only);
	if (ret == ADDR_UNDEF) {
		ERROR(-ERROR_POINT);
	}

	if (ret == ADDR_INSIDE) {
		/* it's an inside address */

		cache->map = NULL;
		cache->type = ADDR_INSIDE;
		cache->addr = addr;

	} else {
		/* it's an outside address */

		cache->type = ret;
		ret = memory_map(addr, &cache->size, &cache->map, &cache->addr, !cache->read_only);
		if (ret < 0) {
			cache->type = ADDR_UNDEF;
			return ret;
		}
		DEBUG_PRINT("Mapping: %p to %p\n", addr, cache->addr);
	}

#ifdef DEBUG
	if (size != cache->size) {
		DEBUG_PRINT("Warning: only %lu bytes of %p where mapped (instead of %lu)\n", cache->size, addr, size);
	}
#endif

	return 0;
}

/* initialize a cache */
void cache_init(arg_cache_t *cache, word len)
{
	word count;

	for (count = 0; count < len; ++count) {
		cache[count].type = ADDR_UNDEF;
		cache[count].size = 0;
	}
}

/* clean a cache */
void cache_clean(arg_cache_t *cache, word len)
{
	word count;

	for (count = 0; count < len; ++count) {
		if (cache[count].type == ADDR_OUTSIDE) {
			DEBUG_PRINT("Unmapping: %p\n", cache[count].map);
			memory_unmap(cache[count].map);
		}
	}
}

/* copy memory using a cache. if the cache was never used, map the unsafe_addr in it */
int cache_memory_copy(byte *unsafe_addr, byte *addr, word offset, word len, word size, arg_cache_t *cache, int write)
{
	int ret = 0;
	word copy_len = len;

	if (cache->type == ADDR_INSIDE || cache->type == ADDR_OUTSIDE) {
		/* the cache is ready */
		goto copy;
	}

	/* map the memory */
	ret = cache_memory_map(unsafe_addr, size, cache, write);
	if (ret < 0) {
		return ret;
	}

copy:

	/* boundary checks */
	if (offset > cache->size) {
		ERROR(-ERROR_OOB);
	}

	if (copy_len > cache->size - offset) {
		copy_len = cache->size - offset;
		ret = -ERROR_OOB;
	}

	/* ...and copy it */

	if (write) {
		if (cache->read_only) {
			ERROR(-ERROR_POINT);
		}
		memory_copy(cache->addr + offset, addr, copy_len);
	} else {
		memory_copy(addr, cache->addr + offset, copy_len);
	}
	if (ret < 0) {
		ERROR(ret);
	}
	return 0;
}

