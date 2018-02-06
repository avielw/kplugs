#include "types.h"
#include "queue.h"
#include "memory.h"
#include "env.h"

void init_queue(struct queue_head *queue, void (*free_data)(void *))
{
	queue->next = NULL;
	queue->last = NULL;
	queue->waiting = 0;
	queue->inter = 0;
	queue->size = 0;
	queue->free_data = free_data;
	spin_lock_init(&queue->lock);
	init_waitqueue_head(&queue->wq);
}

#define handle_interrupt(queue, stop) do { \
	if ((queue)->inter || (stop)) { \
		if (!(--(queue)->waiting)) { \
			if ((queue)->inter != 2) { \
				(queue)->inter = 0; \
			} \
		} \
		spin_unlock_irqrestore(&queue->lock, flags); \
		return -ERROR_INTER; \
	} \
} while (0)

int queue_enqueue(struct queue_head *queue, void *data, int nonblock)
{
	struct queue_node *node = NULL;
	unsigned long flags;
	int stop = 0;
#ifdef __KERNEL__
	struct timespec ts1, ts2;

	if (in_atomic()) {
		getnstimeofday(&ts1);
	}
#endif
	spin_lock_irqsave(&queue->lock, flags);
	if (queue->inter) {
		spin_unlock_irqrestore(&queue->lock, flags);
		return -ERROR_INTER;
	}

	queue->waiting++;
	while (queue->size >= MAX_QUEUE_SIZE) {
		spin_unlock_irqrestore(&queue->lock, flags);
        if (nonblock) {
            return -ERROR_BLOCK;
        }
#ifdef __KERNEL__
		if (in_atomic()) {
			/* we have to do a busy wait */
			getnstimeofday(&ts2);
			if (((timespec_to_ns(&ts2) - timespec_to_ns(&ts1)) / 1000000) >= MAX_BUSY_WAIT) {
				stop = 1;
			}
		} else {
			if (wait_event_interruptible(queue->wq, (queue->size < MAX_QUEUE_SIZE || queue->inter))) {
				stop = 1;
			}
		}
#endif
		spin_lock_irqsave(&queue->lock, flags);
		handle_interrupt(queue, stop);
	}
	queue->waiting--;

	node = memory_alloc(sizeof(struct queue_node));
	if (NULL == node) {
		spin_unlock_irqrestore(&queue->lock, flags);
		return -ERROR_MEM;
	}
	node->data = data;
	node->next = queue->next;
	node->prev = NULL;
	if (NULL != node->next) {
		node->next->prev = node;
	}
	if (NULL == queue->last) {
		queue->last = node;
	}
	queue->next = node;
	queue->size++;

	wake_up_interruptible(&queue->wq);
	spin_unlock_irqrestore(&queue->lock, flags);
	return 0;
}

int queue_dequeue(struct queue_head *queue, void **data, int nonblock)
{
	struct queue_node *node = NULL;
	unsigned long flags;
	int stop = 0;
#ifdef __KERNEL__
	struct timespec ts1, ts2;

	if (in_atomic()) {
		getnstimeofday(&ts1);
	}
#endif

	spin_lock_irqsave(&queue->lock, flags);
	if (queue->inter) {
		spin_unlock_irqrestore(&queue->lock, flags);
		return -ERROR_INTER;
	}

	queue->waiting++;
	while (!queue->size) {
		spin_unlock_irqrestore(&queue->lock, flags);
        if (nonblock) {
            return -ERROR_BLOCK;
        }
#ifdef __KERNEL__
		if (in_atomic()) {
			/* we have to do a busy wait */
			getnstimeofday(&ts2);
			if (((timespec_to_ns(&ts2) - timespec_to_ns(&ts1)) / 1000000) >= MAX_BUSY_WAIT) {
				stop = 1;
			}
		} else {
			if (wait_event_interruptible(queue->wq, (queue->size || queue->inter))) {
				stop = 1;
			}
		}
#endif
		spin_lock_irqsave(&queue->lock, flags);
		handle_interrupt(queue, stop);
	}
	queue->waiting--;

	node = queue->last;
	if (NULL == node) {
		/* we should not be here! */
		spin_unlock_irqrestore(&queue->lock, flags);
		return -ERROR_MEM;
	}
	*data = node->data;
	queue->size--;
	queue->last = node->prev;
	if (NULL != queue->last) {
		queue->last->next = NULL;
	}
	if (queue->next == node) {
		queue->next = NULL;
	}
	memory_free(node);

	wake_up_interruptible(&queue->wq);
	spin_unlock_irqrestore(&queue->lock, flags);
	return 0;
}

void queue_kill(struct queue_head *queue)
{
	struct queue_node *node;
	unsigned long flags;

	spin_lock_irqsave(&queue->lock, flags);

	node = queue->next;
	while (node) {
		queue->next = node->next;
		queue->free_data(node->data);
		memory_free(node);
		node = queue->next;
	}

	queue->last = NULL;
	queue->inter = 2;
	wake_up_interruptible(&queue->wq);
	spin_unlock_irqrestore(&queue->lock, flags);
}

void queue_interrupt(struct queue_head *queue)
{
	unsigned long flags;

	spin_lock_irqsave(&queue->lock, flags);
	if (queue->waiting) {
		queue->inter = 1;
		wake_up_interruptible(&queue->wq);
	}
	spin_unlock_irqrestore(&queue->lock, flags);
}
