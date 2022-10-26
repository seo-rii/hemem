#ifndef HEMEM_FIFO_H
#define HEMEM_FIFO_H

#include <pthread.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include "hemem-ucm.h"

struct page_list {
  struct hemem_page *first, *last;
  pthread_mutex_t list_lock;
  size_t numentries;
};

struct process_list {
  struct hemem_process *first, *last;
  pthread_mutex_t list_lock;
  size_t numentries;
};


void enqueue_page(struct page_list *list, struct hemem_page *page);
struct hemem_page* dequeue_page(struct page_list *list);
void page_list_remove(struct page_list *list, struct hemem_page *page);
struct hemem_page* prev_page(struct page_list *list, struct hemem_page *page);

void enqueue_process(struct process_list *list, struct hemem_process *process);
struct hemem_process* dequeue_process(struct process_list *list);
void process_list_remove(struct process_list *list, struct hemem_process *process);

#endif

