#include <pthread.h>
#include <stdlib.h>

#include "hemem.h"
#include "fifo.h"

void enqueue_fifo(struct fifo_list *queue, struct hemem_page *entry)
{
  pthread_mutex_lock(&(queue->list_lock));
  assert(entry->prev == NULL);
  entry->next = queue->first;
  if(queue->first != NULL) {
    assert(queue->first->prev == NULL);
    queue->first->prev = entry;
  } else {
    assert(queue->last == NULL);
    assert(queue->numentries == 0);
    queue->last = entry;
  }

  queue->first = entry;
  entry->list = queue;
  queue->numentries++;
  pthread_mutex_unlock(&(queue->list_lock));
}

struct hemem_page *dequeue_fifo(struct fifo_list *queue)
{
  pthread_mutex_lock(&(queue->list_lock));
  struct hemem_page *ret = queue->last;

  if(ret == NULL) {
    //assert(queue->numentries == 0);
    pthread_mutex_unlock(&(queue->list_lock));
    return ret;
  }

  queue->last = ret->prev;
  if(queue->last != NULL) {
    queue->last->next = NULL;
  } else {
    queue->first = NULL;
  }

  ret->prev = ret->next = NULL;
  ret->list = NULL;
  assert(queue->numentries > 0);
  queue->numentries--;
  pthread_mutex_unlock(&(queue->list_lock));

  return ret;
}

void page_list_remove_page(struct fifo_list *list, struct hemem_page *page)
{
  pthread_mutex_lock(&(list->list_lock));
  if (list->first == NULL) {
    assert(list->last == NULL);
    assert(list->numentries == 0);
    pthread_mutex_unlock(&(list->list_lock));
    LOG("page_list_remove_page: list was empty!\n");
    return;
  }

  if (list->first == page) {
    list->first = page->next;
  }

  if (list->last == page) {
    list->last = page->prev;
  }

  if (page->next != NULL) {
    page->next->prev = page->prev;
  }

  if (page->prev != NULL) {
    page->prev->next = page->next;
  }

  assert(list->numentries > 0);
  list->numentries--;
  page->next = NULL;
  page->prev = NULL;
  page->list = NULL;
  pthread_mutex_unlock(&(list->list_lock));
}

void merge_page_list(struct fifo_list *src, struct fifo_list *target) {
  pthread_mutex_lock(&(src->list_lock));
  pthread_mutex_lock(&(target->list_lock));

  if(src->last != NULL) {
    src->last->next = target->first;
  }
  if(target->first != NULL) {
    target->first->prev = src->last;
  }

  if(src->first == NULL) {
    src->first = target->first;
  }
  if(target->last != NULL) {
    src->last = target->last;
  }
  
  src->numentries += target->numentries;
  target->numentries = 0;
  target->first = NULL;
  target->last = NULL;

  pthread_mutex_unlock(&(target->list_lock));
  pthread_mutex_unlock(&(src->list_lock));
}
#ifndef HISTOGRAM
void next_page(struct fifo_list *list, struct hemem_page *page, struct hemem_page **next_page)
{
    pthread_mutex_lock(&(list->list_lock));
    if (page == NULL) {
        *next_page = list->last;
    }
    else {
        *next_page = page->prev;
        assert(page->list == list);
    }
    pthread_mutex_unlock(&(list->list_lock));
}
#else
void next_page(struct fifo_list *base, struct hemem_page *page, struct hemem_page **next_page)
{
    struct fifo_list *list;
    struct hemem_page *p = NULL;

    if(page == NULL) {
      list = base + MAX_HISTOGRAM_BINS - 1;
    } else {
      assert(page->list != NULL);
      list = page->list;
    }

    while(p == NULL && list >= base) {
      pthread_mutex_lock(&(list->list_lock));
      if (page == NULL || list != page->list) {
          p = list->last;
      }
      else {
          p = page->prev;
      }
      pthread_mutex_unlock(&(list->list_lock));
      list--;
    }

    *next_page = p;
}
#endif

#ifdef HISTOGRAM
void prev_page(struct fifo_list *base, struct hemem_page *page, struct hemem_page **prev_page)
{
    struct fifo_list *list;
    struct hemem_page *p = NULL;

    if(page == NULL) {
      list = base;
    } else {
      assert(page->list != NULL);
      list = page->list;
    }

    while(p == NULL && list < base + MAX_HISTOGRAM_BINS) {
      pthread_mutex_lock(&(list->list_lock));
      if (page == NULL || list != page->list) {
          p = list->first;
      }
      else {
          p = page->next;
      }
      pthread_mutex_unlock(&(list->list_lock));
      list++;
    }

    *prev_page = p;
}
#endif
