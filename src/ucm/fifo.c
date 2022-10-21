#include <pthread.h>
#include <stdlib.h>

#include "hemem-ucm.h"
#include "fifo.h"
#include "logging.h"

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

struct hemem_page *dequeue_fifo(struct fifo_list *queue, enum dequeue_policy policy)
{
  pthread_mutex_lock(&(queue->list_lock));
  struct hemem_page *ret = queue->last;

  if(ret == NULL) {
    //assert(queue->numentries == 0);
    pthread_mutex_unlock(&(queue->list_lock));
    return ret;
  }

  // Default, just return last page
  if(policy == DEQ_NONE) {
      queue->last = ret->prev;
      if(queue->last != NULL) {
        queue->last->next = NULL;
      } else {
        queue->first = NULL;
      }
  }
  // If we want to choose lowest or highest density, we peek a few pages and see
  else {
    uint64_t chosen_index = 0;
    uint64_t chosen_density = ret->density;
    for(int i = 0; i < DEQUEUE_PEEK_PAGES; ++i) {
      if(ret == NULL)
        break;
      // Choose new page with larger density
      if(policy == DEQ_HIGHEST_DENSITY && ret->density > chosen_density) {
        chosen_density = ret->density;
        chosen_index = i;
      }
      // Choose new page with lower density
      else if(policy == DEQ_LOWEST_DENSITY && ret->density < chosen_density) {
        chosen_density = ret->density;
        chosen_index = i;
      }
      ret = ret->next;
    }
    // Now go through queue again, and find chosen page
    ret = queue->last;
    for (size_t i = 0; i < chosen_index; i++) {
      ret = ret->next;
    }
    // If last page, reset queue stuff
    if(chosen_index == 0) {
      queue->last = ret->prev;
      if(queue->last != NULL) {
        queue->last->next = NULL;
      } else {
        queue->first = NULL;
      }
    }
    // Otherwise extract from position in queue
    else {
      if(ret->prev != NULL)
        ret->prev->next = ret->next;
      if(ret->next != NULL)
        ret->next->prev = ret->prev;
    }
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
    //LOG("page_list_remove_page: list was empty!\n");
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
