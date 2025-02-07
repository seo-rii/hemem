#define _GNU_SOURCE
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <pthread.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <sys/mman.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <math.h>
#include <signal.h>

#include "pebs.h"
#include "hemem.h"
#include "timer.h"
#include "spsc-ring.h"

#ifdef HISTOGRAM
struct fifo_list dram_histogram_list[MAX_HISTOGRAM_BINS];
struct fifo_list nvm_histogram_list[MAX_HISTOGRAM_BINS];
uint64_t histogram_clock = 0;
#else
struct fifo_list dram_hot_list;
struct fifo_list dram_cold_list;
struct fifo_list nvm_hot_list;
struct fifo_list nvm_cold_list;
#endif
struct fifo_list dram_free_list;
struct fifo_list nvm_free_list;
#ifndef HISTOGRAM
ring_handle_t hot_ring;
ring_handle_t cold_ring;
#else
ring_handle_t update_ring;
#endif

volatile bool need_cool_dram;
volatile bool need_cool_nvm;

struct hemem_page* start_dram_page;
struct hemem_page* start_nvm_page;

uint64_t global_clock;

void pebs_migrate_down(struct hemem_page *page, uint64_t offset)
{
  struct timeval start, end;

  gettimeofday(&start, NULL);

  if(page->list == &dram_free_list || page->list == &nvm_free_list) {
    printf("BUG: attempting to migrate freed page\n");
  }

  if(page->present == false) {
    printf("BUG: attempting to migrate un-processed free page\n"); 
  }

  page->migrating = true;
  hemem_wp_page(page, true);
  hemem_migrate_down(page, offset);
  page->migrating = false; 

  gettimeofday(&end, NULL);
  LOG_TIME("migrate_down: %f s\n", elapsed(&start, &end));
}

void pebs_migrate_up(struct hemem_page *page, uint64_t offset)
{
  struct timeval start, end;

  gettimeofday(&start, NULL);

  if(page->list == &dram_free_list || page->list == &nvm_free_list) {
    printf("BUG: attempting to migrate freed page\n");
  }

  if(page->present == false) {
    printf("BUG: attempting to migrate un-processed free page\n"); 
  }

  page->migrating = true;
  hemem_wp_page(page, true);
  hemem_migrate_up(page, offset);
  page->migrating = false;

  gettimeofday(&end, NULL);
  LOG_TIME("migrate_up: %f s\n", elapsed(&start, &end));
}


#ifndef HISTOGRAM
void make_hot_request(struct hemem_page* page)
{
   page->ring_present = true;
   ring_buf_put(hot_ring, (uint64_t*)page); 
}

void make_cold_request(struct hemem_page* page)
{
    page->ring_present = true;
    ring_buf_put(cold_ring, (uint64_t*)page);
}
#else
void histogram_update_request(struct hemem_page* page) 
{
  page->ring_present = true;
  ring_buf_put(update_ring, (uint64_t*)page); 
}
#endif



#ifdef HISTOGRAM
// Should be called before doing any list operations
// void histogram_sync_page(struct hemem_page* page) {
//   int old_bin, new_bin;
//   struct fifo_list *base_ptr;
//   assert(page != NULL);

//   if(page->list == NULL) {
//     return;
//   }

//   // Make sure page->list back pointer is up-to-date
//   if(page->local_histogram_clock != histogram_clock) {
//     assert(histogram_clock > page->local_histogram_clock);
//     base_ptr = (page->in_dram)?(&dram_histogram_list[0]):(&nvm_histogram_list[0]);
//     old_bin = (int)(page->list - base_ptr);
//     assert(old_bin >= 0 && old_bin < MAX_HISTOGRAM_BINS);
//     new_bin = (old_bin >> (histogram_clock - page->local_histogram_clock));
//     page->list = base_ptr + new_bin;
//     page->local_histogram_clock = histogram_clock;
//   }
// }
bool histogram_update(struct hemem_page* page, uint64_t accesses)
{
  struct fifo_list *cur_list;
  struct fifo_list *new_list;
  bool ret = false;
  int bin;
  assert(page != NULL);
  assert(page->va != 0);

  // histogram_sync_page(page);
  cur_list = page->list;
  bin = accesses;
  if(bin >= MAX_HISTOGRAM_BINS) {
    bin = MAX_HISTOGRAM_BINS - 1;
  }
  new_list = (page->in_dram)?(&dram_histogram_list[bin]):(&nvm_histogram_list[bin]);
  
  if(cur_list != new_list) {
    if(cur_list != NULL) {
      page_list_remove_page(cur_list, page);
      ret = true;
      if(page->prev != NULL) {
        printf("page->prev not NULL after list remove");
        fflush(stdout);
      }
    }
    // page->local_histogram_clock = histogram_clock;
    if(page->prev != NULL) {
      printf("page->prev not NULL before enqueue\n");
      fflush(stdout);
    }
    enqueue_fifo(new_list, page);
  }

  return ret;
}

// Left shift all bins in histogram by a factor
// NOTE: individual page->list pointers are not updated
// void histogram_shift(struct fifo_list *hist, unsigned int factor) {
//   int shifted_bin;
//   if(factor == 0) {
//     return;
//   }
//   for(int i = 0; i < MAX_HISTOGRAM_BINS; i++) {
//     shifted_bin = (i >> factor);
//     if(shifted_bin != i) {
//       merge_page_list(hist + shifted_bin, hist + i);
//     }
//   }
// }
#else
// moves page to hot list -- called by migrate thread
void make_hot(struct hemem_page* page)
{
  assert(page != NULL);
  assert(page->va != 0);

  if (page->hot) {
    if (page->in_dram) {
      assert(page->list == &dram_hot_list);
    }
    else {
      assert(page->list == &nvm_hot_list);
    }

    return;
  }

  if (page->in_dram) {
    if(page->list != &dram_cold_list) {
	          printf("cold dram page not in dram cold list. page->present: %d, page->va=%lu, page->list=%p, dram_hot_list=%p, dram_cold_list=%p, nvm_hot_list=%p, nvm_cold_list=%p, dram_free_list=%p, nvm_free_list=%p, page->devdax_offset=%lu, page->migrating=%d, page->naccesses=%lu, page->accesses_dram=%lu, page->accesses_nvm=%lu, page->tot_accesses_dram=%lu, page->tot_accesses_nvm=%lu, page->migrations_up=%lu, page->migrations_down=%lu\n", page->present, page->va, page->list, &dram_hot_list, &dram_cold_list, &nvm_hot_list, &nvm_cold_list, &dram_free_list, &nvm_free_list, page->devdax_offset, page->migrating, page->naccesses, page->accesses[DRAMREAD], page->accesses[NVMREAD], page->tot_accesses[DRAMREAD], page->tot_accesses[NVMREAD], page->migrations_up, page->migrations_down);
	}
    assert(page->list == &dram_cold_list);
    page_list_remove_page(&dram_cold_list, page);
    page->hot = true;
    enqueue_fifo(&dram_hot_list, page);
  }
  else {
    assert(page->list == &nvm_cold_list);
    page_list_remove_page(&nvm_cold_list, page);
    page->hot = true;
    enqueue_fifo(&nvm_hot_list, page);
  }
}

// moves page to cold list -- called by migrate thread
void make_cold(struct hemem_page* page)
{
  assert(page != NULL);
  assert(page->va != 0);

  if (!page->hot) {
    if (page->in_dram) {
      if(page->list != &dram_cold_list) {
        printf("cold dram page not in dram cold list. page->present: %d, page->va=%lu, page->list=%p, dram_hot_list=%p, dram_cold_list=%p, nvm_hot_list=%p, nvm_cold_list=%p, page->devdax_offset=%lu, page->migrating=%d, page->naccesses=%lu, page->accesses_dram=%lu, page->accesses_nvm=%lu, page->tot_accesses_dram=%lu, page->tot_accesses_nvm=%lu, page->migrations_up=%lu, page->migrations_down=%lu\n", page->present, page->va, page->list, &dram_hot_list, &dram_cold_list, &nvm_hot_list, &nvm_cold_list, page->devdax_offset, page->migrating, page->naccesses, page->accesses[DRAMREAD], page->accesses[NVMREAD], page->tot_accesses[DRAMREAD], page->tot_accesses[NVMREAD], page->migrations_up, page->migrations_down);
      }
      assert(page->list == &dram_cold_list);
    }
    else {
      if(page->list != &nvm_cold_list) {
        printf("cold nvm page not in nvm cold list. page->present: %d, page->va=%lu, page->list=%p, dram_hot_list=%p, dram_cold_list=%p, nvm_hot_list=%p, nvm_cold_list=%p, page->devdax_offset=%lu, page->migrating=%d, page->naccesses=%lu, page->accesses_dram=%lu, page->accesses_nvm=%lu, page->tot_accesses_dram=%lu, page->tot_accesses_nvm=%lu, page->migrations_up=%lu, page->migrations_down=%lu\n", page->present, page->va, page->list, &dram_hot_list, &dram_cold_list, &nvm_hot_list, &nvm_cold_list, page->devdax_offset, page->migrating, page->naccesses, page->accesses[DRAMREAD], page->accesses[NVMREAD], page->tot_accesses[DRAMREAD], page->tot_accesses[NVMREAD], page->migrations_up, page->migrations_down);
      }
      assert(page->list == &nvm_cold_list);
    }

    return;
  }

  if (page->in_dram) {
    assert(page->list == &dram_hot_list);
    page_list_remove_page(&dram_hot_list, page);
    page->hot = false;
    enqueue_fifo(&dram_cold_list, page);
  }
  else {
    if(page->list != &nvm_hot_list) {
      printf("hot nvm page not in nvm hot list. page->present: %d, page->va=%lu, page->list=%p, dram_hot_list=%p, dram_cold_list=%p, nvm_hot_list=%p, nvm_cold_list=%p, page->devdax_offset=%lu, page->migrating=%d, page->naccesses=%lu, page->accesses_dram=%lu, page->accesses_nvm=%lu, page->tot_accesses_dram=%lu, page->tot_accesses_nvm=%lu, page->migrations_up=%lu, page->migrations_down=%lu\n", page->present, page->va, page->list, &dram_hot_list, &dram_cold_list, &nvm_hot_list, &nvm_cold_list, page->devdax_offset, page->migrating, page->naccesses, page->accesses[DRAMREAD], page->accesses[NVMREAD], page->tot_accesses[DRAMREAD], page->tot_accesses[NVMREAD], page->migrations_up, page->migrations_down);
    }
    assert(page->list == &nvm_hot_list);
    page_list_remove_page(&nvm_hot_list, page);
    page->hot = false;
    enqueue_fifo(&nvm_cold_list, page);
  }
}
#endif


#ifdef SCAN_AND_SORT
int scan_page_list(struct fifo_list *page_list, struct page_freq *page_freqs, size_t freqs_size, uint64_t *total_accesses) {
  int idx = 0;
  struct hemem_page *p;
  struct hemem_page *np;
  next_page(page_list, NULL, &p);
  while(p != NULL) {
    // There could be pages that were unmapped, but not yet moved to free list
    // Don't want to consider these for migration
    if(p->present) {
      assert(idx < freqs_size);
      #ifdef COLLOID_COOLING
      page_freqs[idx].accesses = (p->accesses[DRAMREAD] >> (global_clock - p->local_clock)) + (p->accesses[NVMREAD] >> (global_clock - p->local_clock));
      #else
      page_freqs[idx].accesses = p->tot_accesses[DRAMREAD] + p->tot_accesses[NVMREAD];
      #endif
      page_freqs[idx].page = p;
      *total_accesses += page_freqs[idx].accesses;
      idx += 1;
    }
    next_page(page_list, p, &np);
    p = np;
  }
  return idx;
}
int cmp_page_freq (const void * a, const void * b) {
   return ( ((struct page_freq*)a)->accesses - ((struct page_freq*)b)->accesses );
}
#endif

#ifdef COOL_IN_PLACE
void update_current_cool_page(struct hemem_page** cur_cool_in_dram, struct hemem_page** cur_cool_in_nvm, struct hemem_page* page)
{
    if (page == NULL) {
        return;
    }

    if (page == *cur_cool_in_dram) {
        #ifdef HISTOGRAM
        assert(page->in_dram);
        next_page(&dram_histogram_list[0], page, cur_cool_in_dram);
        #else
        assert(page->list == &dram_hot_list);
        next_page(page->list, page, cur_cool_in_dram);
        #endif
    }
    if (page == *cur_cool_in_nvm) {
        #ifdef HISTOGRAM
        assert(!page->in_dram);
        next_page(&nvm_histogram_list[0], page, cur_cool_in_nvm);
        #else
        assert(page->list == &nvm_hot_list);
        next_page(page->list, page, cur_cool_in_nvm);
        #endif
    }
}

struct hemem_page* partial_cool(struct fifo_list *hot, struct fifo_list *cold, bool dram, struct hemem_page* current)
{
  struct hemem_page *p;
  #ifdef HISTOGRAM
  struct hemem_page *prev_p;
  #endif
  uint64_t tmp_accesses[NPBUFTYPES];

  if (dram && !need_cool_dram) {
      return current;
  }
  if (!dram && !need_cool_nvm) {
      return current;
  }

  if (start_dram_page == NULL && dram) {
      #ifdef HISTOGRAM
      next_page(hot, NULL, &start_dram_page);
      #else
      start_dram_page = hot->last;
      #endif
  }

  if (start_nvm_page == NULL && !dram) {
      #ifdef HISTOGRAM
      next_page(hot, NULL, &start_nvm_page);
      #else
      start_nvm_page = hot->last;
      #endif
  }

  for (int i = 0; i < COOLING_PAGES; i++) {
    next_page(hot, current, &p);
    if (p == NULL) {
        break;
    }
    if (dram) {
        assert(p->in_dram);
    }
    else {
        assert(!p->in_dram);
    }

    for (int j = 0; j < NPBUFTYPES; j++) {
        tmp_accesses[j] = p->accesses[j] >> (global_clock - p->local_clock);
    }

    if (/*(tmp_accesses[WRITE] < HOT_WRITE_THRESHOLD) &&*/ (tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD] < HOT_READ_THRESHOLD)) {
        p->hot = false;
    }
    
    if (dram && (p == start_dram_page)) {
        start_dram_page = NULL;
        need_cool_dram = false;
    }

    if (!dram && (p == start_nvm_page)) {
        start_nvm_page = NULL;
        need_cool_nvm = false;
    } 

    #ifdef HISTOGRAM
    prev_page(hot, p, &prev_p);
    if(histogram_update(p, tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD])) {
      current = prev_p;      
    } else {
      current = p;
    }
    #else
    if (!p->hot) {
        current = p->next;
        page_list_remove_page(hot, p);
        enqueue_fifo(cold, p);
    }
    else {
        current = p;
    }
    #endif
  }

  return current;
}
#else
void partial_cool(struct fifo_list *hot, struct fifo_list *cold, bool dram)
{
  struct hemem_page *p;
  uint64_t tmp_accesses[NPBUFTYPES];

  if (dram && !need_cool_dram) {
      return;
  }
  if (!dram && !need_cool_nvm) {
      return;
  }

  if ((start_dram_page == NULL) && dram) {
      start_dram_page = hot->last;
  }

  if ((start_nvm_page == NULL) && !dram) {
      start_nvm_page = hot->last;
  }

  for (int i = 0; i < COOLING_PAGES; i++) {
    p = dequeue_fifo(hot);
    if (p == NULL) {
        break;
    }
    if (dram) {
        assert(p->in_dram);
    }
    else {
        assert(!p->in_dram);
    }

    for (int j = 0; j < NPBUFTYPES; j++) {
        tmp_accesses[j] = p->accesses[j] >> (global_clock - p->local_clock);
    }

    if (/*(tmp_accesses[WRITE] < HOT_WRITE_THRESHOLD) &&*/ (tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD] < HOT_READ_THRESHOLD)) {
        p->hot = false;
    }

    if (dram && (p == start_dram_page)) {
        start_dram_page = NULL;
        need_cool_dram = false;
    }

    if (!dram && (p == start_nvm_page)) {
        start_nvm_page = NULL;
        need_cool_nvm = false;
    } 

    if (p->hot) {
      enqueue_fifo(hot, p);
    }
    else {
      enqueue_fifo(cold, p);
    }
  }
}
#endif
