#ifndef QUEUE_H
#define QUEUE_H

#include "types.h"
#include "env.h"

struct queue_node {
	struct queue_node *next;
	struct queue_node *prev;
	void *data;
};

struct queue_head {
	struct queue_node *next;
	struct queue_node *last;
	wait_queue_head_t wq;
	void (*free_data)(void *);
	spinlock_t lock;
	word waiting;
	word size;
	byte inter;
};

void init_queue(struct queue_head *queue, void (*free_data)(void *));

int queue_enqueue(struct queue_head *queue, void *data, int nonblock);
int queue_dequeue(struct queue_head *queue, void **data, int nonblock);

void queue_interrupt(struct queue_head *queue);
void queue_kill(struct queue_head *queue);

#endif
