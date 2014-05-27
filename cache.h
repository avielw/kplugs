#ifndef CACHE_H
#define CACHE_H

typedef struct {
	void *map;
	byte *addr;
	byte type;
	byte read_only;
	word size;
} arg_cache_t;

void cache_init(arg_cache_t *cache, word len);

void cache_clean(arg_cache_t *cache, word len);

/* map a memory to a cache */
int cache_memory_map(byte *addr, word size, arg_cache_t *cache, int write);

int cache_memory_copy(byte *unsafe_addr, byte *addr, word offset, word len, word size, arg_cache_t *cache, int write);

#define IS_CACHED(cache) ((cache)->type != ADDR_UNDEF)

#endif
