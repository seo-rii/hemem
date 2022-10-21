#ifndef HEMEM_FIFO_H
#define HEMEM_FIFO_H

#include <pthread.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include "hemem-ucm.h"

#define DEQUEUE_PEEK_PAGES (32)

struct fifo_list {
  struct hemem_page *first, *last;
  pthread_mutex_t list_lock;
  size_t numentries;
};

enum dequeue_policy {
  DEQ_NONE = 0,
  DEQ_HIGHEST_DENSITY = 1,
  DEQ_LOWEST_DENSITY = 2,
};

void enqueue_fifo(struct fifo_list *list, struct hemem_page *page);
struct hemem_page* dequeue_fifo(struct fifo_list *list, enum dequeue_policy policy);
void page_list_remove_page(struct fifo_list *list, struct hemem_page *page);
void next_page(struct fifo_list *list, struct hemem_page *page, struct hemem_page **res);

#endif

