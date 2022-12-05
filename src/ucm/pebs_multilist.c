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

#include "hemem-ucm.h"
#include "pebs.h"
#include "timer.h"
#include "spsc-ring.h"
#include "logging.h"
#include "hemem-shared.h"

static struct process_list processes_list;
static struct page_list dram_free_list;
static struct page_list nvm_free_list;
uint64_t global_clock = 0;

uint64_t hemem_pages_cnt = 0;
uint64_t other_pages_cnt = 0;
uint64_t other_processes_cnt = 0;
uint64_t total_pages_cnt = 0;
uint64_t zero_pages_cnt = 0;
uint64_t throttle_cnt = 0;
uint64_t unthrottle_cnt = 0;
uint64_t cools = 0;
uint64_t dram_hot_pages = 0;
uint64_t dram_pages_count[NUM_HOTNESS_LEVELS] = {0};
uint64_t nvm_pages_count[NUM_HOTNESS_LEVELS] = {0};
uint64_t stale_candidate_count = 0;

static struct perf_event_mmap_page *perf_page[PEBS_NPROCS][NPBUFTYPES];
int pfd[PEBS_NPROCS][NPBUFTYPES];

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, 
    int cpu, int group_fd, unsigned long flags)
{
  int ret;

  ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
		group_fd, flags);
  return ret;
}

static struct perf_event_mmap_page* perf_setup(__u64 config, __u64 config1, __u64 cpu, __u64 type)
{
  struct perf_event_attr attr;

  memset(&attr, 0, sizeof(struct perf_event_attr));

  attr.type = PERF_TYPE_RAW;
  attr.size = sizeof(struct perf_event_attr);

  attr.config = config;
  attr.config1 = config1;
  attr.sample_period = SAMPLE_PERIOD;

  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_ADDR;
  attr.disabled = 0;
  //attr.inherit = 1;
  attr.exclude_kernel = 1;
  attr.exclude_hv = 1;
  attr.exclude_callchain_kernel = 1;
  attr.exclude_callchain_user = 1;
  attr.precise_ip = 1;

  pfd[cpu][type] = perf_event_open(&attr, -1, cpu, -1, 0);
  if(pfd[cpu][type] == -1) {
    perror("perf_event_open");
  }
  assert(pfd[cpu][type] != -1);

  size_t mmap_size = sysconf(_SC_PAGESIZE) * PERF_PAGES;
  /* printf("mmap_size = %zu\n", mmap_size); */
  struct perf_event_mmap_page *p = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, pfd[cpu][type], 0);
  if(p == MAP_FAILED) {
    perror("mmap");
  }
  assert(p != MAP_FAILED);

  return p;
}

void make_hot_request(struct hemem_process* process, struct hemem_page* page)
{
   page->ring_present = true;
   ring_buf_put(process->hot_ring, (uint64_t*)page);
}

void make_cold_request(struct hemem_process* process, struct hemem_page* page)
{
    page->ring_present = true;
    ring_buf_put(process->cold_ring, (uint64_t*)page);
}

int access_to_index(uint64_t num) {
  if(num == 0) {
    return 0;
  }
  return (num/3) + 1;
}

// int access_to_index(uint64_t num) {
//   if(num <= 0) {
//     return 0;
//   }
//   int ret = 64-__builtin_clzll(num);
//   if(ret > NUM_HOTNESS_LEVELS-1) {
//     return NUM_HOTNESS_LEVELS-1;
//   }
//   return ret;
// }

void *pebs_scan_thread()
{
  cpu_set_t cpuset;
  pthread_t thread;

  thread = pthread_self();
  CPU_ZERO(&cpuset);
  CPU_SET(SCANNING_THREAD_CPU, &cpuset);
  int s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (s != 0) {
    perror("pthread_setaffinity_np");
    assert(0);
  }

  for(;;) {
    for (int i = 4; i < PEBS_NPROCS - 1; i++) {
      for(int j = 0; j < NPBUFTYPES; j++) {
        struct perf_event_mmap_page *p = perf_page[i][j];
        char *pbuf = (char *)p + p->data_offset;

        __sync_synchronize();

        if(p->data_head == p->data_tail) {
          continue;
        }

        struct perf_event_header *ph = (void *)(pbuf + (p->data_tail % p->data_size));
        struct perf_sample* ps;
        struct hemem_page* page;
        struct hemem_process* process;

        switch(ph->type) {
        case PERF_RECORD_SAMPLE:
            ps = (struct perf_sample*)ph;
            assert(ps != NULL);
            if(ps->addr != 0) {
              __u64 pfn = ps->addr & HUGE_PFN_MASK;
              process = find_process(ps->pid);

              if (process != NULL) {
                page = find_page(process, pfn);
                if (page != NULL) {
                  if (page->va != 0) {
#ifdef HEMEM_QOS
                    process->accessed_pages[j]++;
#endif
                    page->accesses[j]++;
                    page->tot_accesses[j]++;

                    uint64_t total_accesses = page->accesses[DRAMREAD] + page->accesses[NVMREAD];
                    int new_hotness = access_to_index(total_accesses);
                    // check for hotness change and add to ring
                    if(new_hotness > page->hot) {
                      make_hot_request(process, page);
                    }
                    else if(new_hotness < page->hot) {
                      make_cold_request(process, page);
                    }

                    page->accesses[DRAMREAD] >>= (global_clock - page->local_clock);
                    page->accesses[NVMREAD] >>= (global_clock - page->local_clock);
                    page->local_clock = global_clock;
                    if (page->accesses[j] > PEBS_COOLING_THRESHOLD) {
                      global_clock++;
                      cools++;
                      process->need_cool = true;
                    }
                  }
                  hemem_pages_cnt++;
                }
                else {
                  other_pages_cnt++;
                }
                total_pages_cnt++;
              }
              else {
                other_processes_cnt++;
              }
            }
            else {
              zero_pages_cnt++;
            }
  	      break;
        case PERF_RECORD_THROTTLE:
        case PERF_RECORD_UNTHROTTLE:
          if (ph->type == PERF_RECORD_THROTTLE) {
              throttle_cnt++;
          }
          else {
              unthrottle_cnt++;
          }
          break;
        default:
          fprintf(stderr, "Unknown type %u\n", ph->type);
          //assert(!"NYI");
          break;
        }

        p->data_tail += ph->size;
      }
    }
  }

  return NULL;
}

static void pebs_migrate_down(struct hemem_process *process, struct hemem_page *page, uint64_t offset)
{
  struct timeval start, end;

  gettimeofday(&start, NULL);

  page->migrating = true;
  hemem_ucm_wp_page(page, true);
  hemem_ucm_migrate_down(process, page, offset);
  page->migrating = false; 

  gettimeofday(&end, NULL);
  LOG_TIME("migrate_down: %f s\n", elapsed(&start, &end));
}

static void pebs_migrate_up(struct hemem_process *process, struct hemem_page *page, uint64_t offset)
{
  struct timeval start, end;

  gettimeofday(&start, NULL);

  page->migrating = true;
  hemem_ucm_wp_page(page, true);
  hemem_ucm_migrate_up(process, page, offset);
  page->migrating = false;

  gettimeofday(&end, NULL);
  LOG_TIME("migrate_up: %f s\n", elapsed(&start, &end));
}

// moves page to hot list -- called by migrate thread
void make_hot(struct hemem_process* process, struct hemem_page* page, int newhot)
{
  assert(page != NULL);
  assert(page->va != 0);

  if (page->hot == newhot) {
    if (page->in_dram) {
      assert(page->list == &(process->dram_lists[newhot]));
    }
    else {
      assert(page->list == &(process->nvm_lists[newhot]));
    }

    return;
  }

  if (page->in_dram) {
    assert(page->list == &(process->dram_lists[page->hot]));
    page_list_remove(&(process->dram_lists[page->hot]), page);
    page->hot = newhot;
    enqueue_page(&(process->dram_lists[page->hot]), page);
  }
  else {
    assert(page->list == &(process->nvm_lists[page->hot]));
    page_list_remove(&(process->nvm_lists[page->hot]), page);
    page->hot = newhot;
    enqueue_page(&(process->nvm_lists[page->hot]), page);
  }
}

// moves page to cold list -- called by migrate thread
void make_cold(struct hemem_process* process, struct hemem_page* page, int newhot)
{
  assert(page != NULL);
  assert(page->va != 0);

  if (page->hot == newhot) {
    if (page->in_dram) {
      assert(page->list == &(process->dram_lists[newhot]));
    }
    else {
      assert(page->list == &(process->nvm_lists[newhot]));
    }

    return;
  }

  if (page->in_dram) {
    assert(page->list == &(process->dram_lists[page->hot]));
    page_list_remove(&(process->dram_lists[page->hot]), page);
    page->hot = newhot;
    enqueue_page(&(process->dram_lists[page->hot]), page);
  }
  else {
    assert(page->list == &(process->nvm_lists[page->hot]));
    page_list_remove(&(process->nvm_lists[page->hot]), page);
    page->hot = newhot;
    enqueue_page(&(process->nvm_lists[page->hot]), page);
  }
}

struct hemem_page* partial_cool(struct hemem_process* process, bool dram)
{
  struct hemem_page *p, *current;
  uint64_t tmp_accesses[NPBUFTYPES];
  int cool_list, cur_list_index;
  bool goto_next_list = false;
  struct page_list* cur_bins;
  struct page_list* temp;

  // do we even need to be cooling right now? If not, just return
  // where we left off last time we needed to cool. Next time this function
  // is called when cooling is needed, we pick up from here
  if (dram && !(process->need_cool)) {
    return process->cur_cool_in_dram;
  } else if (!dram && !(process->need_cool)) {
    return process->cur_cool_in_nvm;
  }

  // we cool backwards through the page lists, the same order the 
  // were inserted. The idea is, in this way, we cool the oldest pages 
  if (dram && (process->cur_cool_in_dram == NULL) && (process->cur_cool_in_dram_list == 0)) {
      for(int i = NUM_HOTNESS_LEVELS-1; i > 0 && process->cur_cool_in_dram == NULL; i--) {
        process->cur_cool_in_dram = process->dram_lists[i].last;
        process->cur_cool_in_dram_list = i;
      }
      // dram hot list might be empty, in which case we have nothing to cool
      if (process->cur_cool_in_dram == NULL) {
        process->cur_cool_in_dram_list = 0;
        process->need_cool = false;
        return NULL;
      }
  } else if ((!dram) && (process->cur_cool_in_nvm == NULL) && (process->cur_cool_in_nvm_list == 0)) {
      for(int i = NUM_HOTNESS_LEVELS-1; i > 0 && process->cur_cool_in_nvm == NULL; i--) {
        process->cur_cool_in_nvm = process->nvm_lists[i].last;
        process->cur_cool_in_nvm_list = i;
      }
      // dram hot list might be empty, in which case we have nothing to cool
      if (process->cur_cool_in_nvm == NULL) {
        process->cur_cool_in_nvm_list = 0;
        process->need_cool = false;
        return NULL;
      }
  }

  // set hot and cold list pointers as appropriate for memory type
  // set current to the current cooled page for the memory type here as well
  if (dram) {
    current = process->cur_cool_in_dram;
    cool_list = process->cur_cool_in_dram_list;
    cur_bins = process->dram_lists;
    if(current)
      assert(current->list == &(cur_bins[current->hot]));
  } else {
    current = process->cur_cool_in_nvm;
    cool_list = process->cur_cool_in_nvm_list;
    cur_bins = process->nvm_lists;
    if(current)
      assert(current->list == &(cur_bins[current->hot]));
  }
  
  // start from the current cooled page. This is either where we left off
  // last time or the end of the page list if we've gone throug the whole list
  p = current;
  cur_list_index = cool_list;
  for (int i = 0; i < COOLING_PAGES; i++) {
    if (p == NULL) {
        // not pointing to a page to cool from. check the lower lists. 
        for(int j = cool_list; j > 0 && p == NULL; j--) {
          p = cur_bins[j].last;
          cool_list = j;
        }
        if(p == NULL) {
          cool_list = 0;
          break;
        }
    }

    // sanity check we grabbed a page in the appropriate memory type and
    // from the appropriate list
    if (dram) {
        assert(p->in_dram);
        assert(p->list == &(process->dram_lists[p->hot]));
    } else {
        assert(!p->in_dram);
        assert(p->list == &(process->nvm_lists[p->hot]));
    }

    // compute the access samples this page would have had if it were up to date
    // with cooling
    for (int j = 0; j < NPBUFTYPES; j++) {
        tmp_accesses[j] = p->accesses[j] >> (global_clock - p->local_clock);
    }

    // is the page still hot if it was up to date with cooling?
    int new_hotness = access_to_index((tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD]));
    if (new_hotness != p->hot) {
        // if the page is no longer hot, then we move it to the cold list
        p->hot = new_hotness;
        // first, we update our current pointer in prep for p being
        // moved to the cold list. This ensures our next call to
        // prev_page() stays in the appropriate list
        current = p->next;
        if(current == NULL) {
          goto_next_list = true;
        }
        page_list_remove(p->list, p);
        enqueue_page(&(cur_bins[new_hotness]), p);
    }
    else {
      current = p;
      cur_list_index = cool_list;
    }
    
    // have we gone through the entire hot list? If so, call for the 
    // loop iteration to goto the next list.
    if (dram && (p == process->dram_lists[cool_list].first)) {
      goto_next_list = true;
    } else if (!dram && (p == process->nvm_lists[cool_list].first)) {
      goto_next_list = true;
    } 

    // grab another page to cool
    // first if we need to goto next list then goto that list for the next.
    if(goto_next_list) {
      if(cool_list == 1) {
        cur_list_index = 0;
        current = NULL;
        break;
      }
      goto_next_list = false;
      cool_list--;
      p = cur_bins[cool_list].last;
    }
    else {
      p = prev_page(&(cur_bins[cool_list]), current);
    }
  }

  if(dram) {
    process->cur_cool_in_dram_list = cur_list_index;
  }
  else {
    process->cur_cool_in_nvm_list = cur_list_index;
  }
  return current;
}

// convenience function for catching pages where we migrate or otherwise move a page
// from one list to another. If the page in question was our "bookmark" pointer for
// cooling, then we need to update that bookmark. Here, for simplicity, we just
// reset our bookmark to the end of the hot list
void update_current_cool_page(struct hemem_process *process, struct hemem_page *page)
{
  if (page == process->cur_cool_in_dram) {
    // first a set of sanity checks
    assert(page->in_dram);
    assert(page->list == &(process->dram_lists[page->hot]));
    // then just reset the bookmark pointer to the last page in list
    // just restart
    process->cur_cool_in_dram = NULL;
    process->cur_cool_in_dram_list = 0;
  } else if (page == process->cur_cool_in_nvm) {
    // first, a bunch of sanity checks
    assert(!(page->in_dram));
    assert(page->list == &(process->nvm_lists[page->hot]));
    // then just reset the bookmark pointer to the last page in list
    process->cur_cool_in_nvm = NULL;
    process->cur_cool_in_nvm_list = 0;
  }
}


// The PEBS thread communicates with the policy thread via request rings. The
// only thread allowed to maniuplate the hot and cold lists is the policy thread
// to prevent deadlocks or race conditions, and the ring buffers solve that.
// Here, the policy thread will handle the ring buffer requests by placing
// the pages in the ring buffers into the appropriate lists
void handle_ring_requests(struct hemem_process *process)
{
  int num_ring_reqs;
  struct hemem_page* page = NULL;
  uint64_t tmp_accesses[NPBUFTYPES];

  // free pages using free page ring buffer
  // we take all pages from the free ring rather than until
  // meeting some threshold of requests handled to free up
  // as much space as quick as possible
  while(!ring_buf_empty(process->free_page_ring)) {
    struct page_list *list;
    pthread_mutex_lock(&(process->free_page_ring_lock));
    page = (struct hemem_page*)ring_buf_get(process->free_page_ring);
    pthread_mutex_unlock(&(process->free_page_ring_lock));
    if (page == NULL) {
      // ring buffer was empty
      break;
    }
        
    list = page->list;
    assert(list != NULL);

    // list sanity checks
    // either in the correct list or in a ring. 
    if (page->in_dram) {
      assert(page->list == &(process->dram_lists[page->hot]) || page->ring_present);
    } else {
      assert(page->list == &(process->nvm_lists[page->hot]) || page->ring_present);
    }
    
    // check whether the page being freed is our bookmark cool page
    update_current_cool_page(process, page);
    
    // remove page from its list and put it into the appropriate free list
    page_list_remove(list, page);

    // reset page stats
    page->present = false;
    page->hot = false;
    for (int i = 0; i < NPBUFTYPES; i++) {
      page->accesses[i] = 0;
      page->tot_accesses[i] = 0;
    }

    if (page->in_dram) {
      enqueue_page(&dram_free_list, page);
    }
    else {
      enqueue_page(&nvm_free_list, page);
    }
  }

  page = NULL;
  num_ring_reqs = 0;
  // handle hot requests from hot buffer by moving pages to hot list
  while(!ring_buf_empty(process->hot_ring) && num_ring_reqs < HOT_RING_REQS_THRESHOLD) {
	  page = (struct hemem_page*)ring_buf_get(process->hot_ring);
    if (page == NULL) {
      // ring buffer was empty
      break;
    }

    if (!page->present) {
      // page has been freed
      continue;
    }
    
    // compute the access samples this page would have had if it were up to date
    // with cooling
    for (int j = 0; j < NPBUFTYPES; j++) {
        tmp_accesses[j] = page->accesses[j] >> (global_clock - page->local_clock);
    }
    int new_hotness = access_to_index(tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD]);

    // is page even still hot?
    if (new_hotness < page->hot) {
      // page has been cooled and is no longer hot, just move to cold list
      // first, check to see if we need to update our cooling bookmark
      update_current_cool_page(process, page);
      page->ring_present = false;
      num_ring_reqs++;
      make_cold(process, page, new_hotness);
      continue;
    }

    // page is still hot, so we can move it to the hot list
    // do we need to update our cooling bookmark?
    update_current_cool_page(process, page);
    page->ring_present = false;
    num_ring_reqs++;
    make_hot(process, page, new_hotness);
    //printf("hot ring, hot pages:%llu\n", num_ring_reqs);
  }

  page = NULL;
  num_ring_reqs = 0;
  // handle cold requests from cold buffer by moving pages to cold list
  while(!ring_buf_empty(process->cold_ring) && num_ring_reqs < COLD_RING_REQS_THRESHOLD) {
    page = (struct hemem_page*)ring_buf_get(process->cold_ring);
    if (page == NULL) {
      // ring buffer was empty
      break;
    }

    if (!page->present) {
      // page has been freed
      continue;
    }
    
    // compute the access samples this page would have had if it were up to date
    // with cooling
    for (int j = 0; j < NPBUFTYPES; j++) {
        tmp_accesses[j] = page->accesses[j] >> (global_clock - page->local_clock);
    }

    int new_hotness = access_to_index(tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD]);
    if (new_hotness >= page->hot) {
      // page is now hot and should actually move to the hot list
      // if not already there
      update_current_cool_page(process, page);
      page->ring_present = false;
      num_ring_reqs++;
      make_hot(process, page, new_hotness);
      continue;
    }

    // check if we need to update our cooling bookmark, then move page
    // to the cold list
    update_current_cool_page(process, page);
    page->ring_present = false;
    num_ring_reqs++;
    make_cold(process, page, new_hotness);
    //printf("cold ring, cold pages:%llu\n", num_ring_reqs);
  }
}

struct hemem_page* find_cadidate_nvm_page(struct hemem_process *process) {
  struct hemem_page* p;
  struct hemem_page* starting_page;
  for(int i = NUM_HOTNESS_LEVELS-1; i > 0; i--) {
    p = dequeue_page(&(process->nvm_lists[i]));

    if(p == NULL) {
      // got null. list empty. move on.
      continue;
    }
    
    // check if the page is stale in the list. if it is then oops. move on. 
    int tot_accesses = (p->accesses[DRAMREAD] + p->accesses[NVMREAD]) >> (global_clock - p->local_clock);
    starting_page = p;
    while(access_to_index(tot_accesses) < p->hot) {
      if(access_to_index(tot_accesses) < p->hot) {
        stale_candidate_count++;
      }
      enqueue_page(&(process->nvm_lists[i]), p);
      p = dequeue_page(&(process->nvm_lists[i]));
      if(p == starting_page) {
        break;
      }

    }

    if (p != NULL) {
      // found something hot. we should try to promote it.
      return p;
    }
  }
  return NULL;
}

struct hemem_page* find_dram_victim(struct hemem_process *process, int64_t max_hotness) {
  struct hemem_page* p;
  for(int i = 0; i < max_hotness; i++) {
    p = dequeue_page(&(process->dram_lists[i]));
    if (p != NULL) {
      // found something cold. we should try to evict it.
      return p;
    }
  }
  return NULL;
}

void process_migrate_down(struct hemem_process *process, uint64_t migrate_down_bytes)
{
  uint64_t migrated_bytes;
  uint64_t old_offset;
  struct hemem_page *cp, *np;

  for (migrated_bytes = 0; migrated_bytes < migrate_down_bytes;) {
    if (migrated_bytes >= PEBS_MIGRATE_DOWN_RATE) {
      break;
    }

    // get the coldest possible dram page
    for(int i = 0; i < NUM_HOTNESS_LEVELS; i++) {
        cp = dequeue_page(&(process->dram_lists[i]));
        if(cp != NULL) {
            break; 
        }
    }
    if (cp == NULL) {
      break;
    }

    np = dequeue_page(&nvm_free_list);
    if (np != NULL) {
      assert(!(np->present));

      old_offset = cp->devdax_offset;
      pebs_migrate_down(process, cp, np->devdax_offset);
      np->devdax_offset = old_offset;
      np->in_dram = true;
      np->present = false;
      np->hot = false;
      for (int i = 0; i < NPBUFTYPES; i++) {
        np->accesses[i] = 0;
        np->tot_accesses[i] = 0;
      }

      enqueue_page(&(process->nvm_lists[cp->hot]), cp);
      enqueue_page(&dram_free_list, np);
      migrated_bytes += pt_to_pagesize(cp->pt);
    } else {
      // no free NVM pages to move, so put it back into
      // dram cold list and bail out
      enqueue_page(&(process->dram_lists[cp->hot]), cp);
      break;
    }
    //assert(np != NULL);
  }
}

void process_migrate_up(struct hemem_process *process, uint64_t migrate_up_bytes)
{
  uint64_t migrated_bytes;
  uint64_t old_offset;
  uint64_t tmp_accesses[NPBUFTYPES];
  struct hemem_page *p, *np;

  for (migrated_bytes = 0; migrated_bytes < migrate_up_bytes;) {
    if (migrated_bytes >= PEBS_MIGRATE_UP_RATE) {
      break;
    }

    // dequeue hottest pages first for attempting to move up.
    p = find_cadidate_nvm_page(process);
    if(p == NULL) {
        break; // truly nothing in any list.
    }

    if (p == process->cur_cool_in_nvm) {
      process->cur_cool_in_nvm = process->nvm_lists[NUM_HOTNESS_LEVELS-1].last;
    }

    // compute the access samples this page would have had if it were up to date
    // with cooling
    for (int j = 0; j < NPBUFTYPES; j++) {
      tmp_accesses[j] = p->accesses[j] >> (global_clock - p->local_clock);
    }

    int new_hotness = access_to_index(tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD]);
    if (new_hotness == COLD) {
      // page has been cooled and is no longer hot, just move to cold list
      p->hot = new_hotness;
      enqueue_page(&(process->nvm_lists[new_hotness]), p);
      continue;
    }

    // TODO
    // try to find a page for it. in the free list. 
    np = dequeue_page(&dram_free_list);
    if (np == NULL) {
      p->hot = new_hotness;
      enqueue_page(&(process->nvm_lists[p->hot]), p);
      // no free dram pages. look for victim
      break;
    }
    assert(!np->present);

    old_offset = p->devdax_offset;
    pebs_migrate_up(process, p, np->devdax_offset);
    np->devdax_offset = old_offset;
    np->in_dram = false;
    np->present = false;
    np->hot = COLD;
    for (int i = 0; i < NPBUFTYPES; i++) {
      np->accesses[i] = 0;
      np->tot_accesses[i] = 0;
    }

    enqueue_page(&(process->dram_lists[new_hotness]), p);
    p->hot = new_hotness;
    enqueue_page(&nvm_free_list, np);
    migrated_bytes += pt_to_pagesize(p->pt);
  }
}

#ifdef HEMEM_QOS
static inline double calc_miss_ratio(struct hemem_process *process)
{
  return ((1.0 * process->accessed_pages[NVMREAD]) / (process->accessed_pages[DRAMREAD] + process->accessed_pages[NVMREAD]));
}
#endif

int64_t max(int64_t a, int64_t b) {
  return a > b ? a : b;
}

int64_t min(int64_t a, int64_t b) {
  return a < b ? a : b;
}

void *pebs_policy_thread()
{
  cpu_set_t cpuset;
  pthread_t thread;
  int ret;
  uint64_t migrate_up_bytes, migrate_down_bytes;
  struct timeval start, end;
  double migrate_time;
  struct hemem_process *process, *tmp;
#ifdef HEMEM_QOS
  uint64_t requested_dram, remaining_dram, dram_taking;
  struct hemem_process *tmp1;
#endif

  thread = pthread_self();
  CPU_ZERO(&cpuset);
  CPU_SET(MIGRATION_THREAD_CPU, &cpuset);
  ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (ret != 0) {
    perror("pthread_setaffinity_np");
    assert(0);
  }

  for (;;) {
   gettimeofday(&start, NULL);
#ifdef HEMEM_QOS
    // go through once to handle ring requests and calculate current miss ratios 
    process = peek_process(&processes_list);
    while (process != NULL) {
      pthread_mutex_lock(&(process->process_lock));
      handle_ring_requests(process);
      process->victimized = false;

      if (process->accessed_pages[DRAMREAD] + process->accessed_pages[NVMREAD] != 0) {
        process->current_miss_ratio = calc_miss_ratio(process);
        process->accessed_pages[DRAMREAD] = process->accessed_pages[NVMREAD] = 0;
      } else {
        // we use a negative current miss ratio to signal that we don't have
        // any access information for this process yet, so rest of policy thread
        // shouldn't try to manage it for now 
        process->current_miss_ratio = -1.0;
      }

      tmp = process;
      process = process->next;
      pthread_mutex_unlock(&(tmp->process_lock));
    }

    // figure out how much dram we need to reallocate based on ratio diffs
    // if our current miss ratio is less than target, then we are good and
    // can even take dram from this process if needed; if current miss
    // ratio is larger than the target, this process needs more dram
    process = peek_process(&processes_list);
    while (process != NULL) {
      pthread_mutex_lock(&(process->process_lock));

      if (process->current_miss_ratio < 0.0) {
        // skip this process -- we don't have current access information for it
        tmp = process;
        process = process->next;
        pthread_mutex_unlock(&(tmp->process_lock));
        continue;
      }

      if (process->target_miss_ratio >= process->current_miss_ratio) {
        // this process does not need more dram
        tmp = process;
        process = process->next;
        pthread_mutex_unlock(&(tmp->process_lock));
        continue;
      } else {
        // process needs more DRAM, try to give it 1GB
        requested_dram = PEBS_MIGRATE_UP_RATE;
        remaining_dram = requested_dram;
        
        // find a lower priority process to take DRAM from
        tmp = process->next;
        while (tmp != NULL) {
          pthread_mutex_lock(&(tmp->process_lock));
          if ((tmp->current_miss_ratio >= 0.0) && (tmp->target_miss_ratio >= tmp->current_miss_ratio) && !tmp->victimized) {
            // lower priority process has some DRAM it can afford to give up (and we haven't taken from it yet)
            dram_taking = (remaining_dram <= tmp->dram_lists[COLD].numentries * PAGE_SIZE) ? 
                                  remaining_dram : 
                                  (tmp->dram_lists[COLD].numentries * PAGE_SIZE);
            tmp->allowed_dram -= dram_taking;
            tmp->victimized = true;
            remaining_dram -= dram_taking;
          }

          if (remaining_dram == 0) {
            // we found all the dram we needed from the lower priority processes, quit out
            pthread_mutex_unlock(&(tmp->process_lock));
            break;
          }

          tmp1 = tmp;
          tmp = tmp->next;
          pthread_mutex_unlock(&(tmp1->process_lock));
        }

        // if we still need dram, try to find higher priority process to take form
        if (remaining_dram > 0) {
          // we need to take some dram from some higher priority processes
          tmp = peek_process(&(processes_list));
          while (tmp != NULL) {
            if (tmp == process) {
              break;
            }

            pthread_mutex_lock(&(tmp->process_lock));
            if (tmp->target_miss_ratio > process->target_miss_ratio) {
              // lower priority process found, already searched these above, bail out
              pthread_mutex_unlock(&(tmp->process_lock));
              break;
            }
            
            if ((tmp->current_miss_ratio >= 0.0) && (tmp->target_miss_ratio >= tmp->current_miss_ratio) && !tmp->victimized) {
              // lower priority process has some DRAM it can afford to give up (and we haven't taken from it yet)
              dram_taking = (remaining_dram <= tmp->dram_lists[COLD].numentries * PAGE_SIZE) ? 
                                    remaining_dram : 
                                    (tmp->dram_lists[COLD].numentries * PAGE_SIZE);
              tmp->allowed_dram -= dram_taking;
              tmp->victimized = true;
              remaining_dram -= dram_taking;
            }

            if (remaining_dram == 0) {
              // we found all the dram we needed from the lower priority processes, quit out
              pthread_mutex_unlock(&(tmp->process_lock));
              break;
            } 
        
            tmp1 = tmp;
            tmp = tmp->next;
            pthread_mutex_unlock(&(tmp1->process_lock));
          }
        }
        process->allowed_dram += (requested_dram - remaining_dram);
      }
      tmp = process;
      process = process->next;
      pthread_mutex_unlock(&(tmp->process_lock));
    }

    // make room on DRAM for by migrating down pages for each process
    process = peek_process(&processes_list);
    int64_t mig_down_equi = 0;
    while (process != NULL) {
      pthread_mutex_lock(&(process->process_lock));
      if (process->allowed_dram > process->current_dram) {
        // process can have more DRAM, so it can migrate things up if it can
        migrate_down_bytes = 0;
      } else if (process->allowed_dram < process->current_dram) {
        // process has too much dram, so it needs to migrate things down
        migrate_down_bytes = process->current_dram - process->allowed_dram;
      } else {
        // process has correct amount of DRAM, need to migrate down enough pages
        // to free dram for the hot NVM pages. 

        // get number of pages that are in a hotter nvm list than a dram list 
        // do we need a better way to do this with the hot lists? 
        
        // for each hotness in NVM we ask: how many pages of DRAM are we allowed to replace?  
        int64_t temp_dram[NUM_HOTNESS_LEVELS];
        for (int i = 0; i < NUM_HOTNESS_LEVELS; i++) {
          temp_dram[i] = process->dram_lists[i].numentries;
        }
        migrate_down_bytes = 0;
        for (int i = NUM_HOTNESS_LEVELS-1; i > 0; i--) { 
          
          // algo: 
          // -for each NVM hotness we want to get how many pages we can fit into 
          //  DRAM if we swap colder pages
          // -temp_dram is to prevent double counting.
          // 1) how many pages are at this NVM hotness.
          // 2) count how many DRAM pages are lower than this hotness
          // 3) repeat for each DRAM hotness
          int nvm_hot_pages_left_to_migrate = process->nvm_lists[i].numentries;
          for (int j = i-1; j >= 0; j--) {
            // if we got all the hot pages up then we stop checking
            if(nvm_hot_pages_left_to_migrate <= 0) {
              break;
            }
            // if this level of DRAM has no pages left bail.
            if(temp_dram[j] == 0) {
              continue;
            }

            // pages we want from this DRAM level is min(pages at this DRAM level, pages we want to move up)
            int pages_from_cur_dram = min(temp_dram[j], nvm_hot_pages_left_to_migrate);
            temp_dram[j] -= pages_from_cur_dram;
            assert(temp_dram[j] >= 0);
            migrate_down_bytes += pages_from_cur_dram * PAGE_SIZE;
          }
        }
        mig_down_equi = migrate_down_bytes;
      }

      // migrate down first to free up DRAM space
      process_migrate_down(process, migrate_down_bytes);

      tmp = process;
      process = process->next;
      pthread_mutex_unlock(&(tmp->process_lock));
    }
    
    // fill DRAM by migrating up pages for each process
    process = peek_process(&processes_list);
    while (process != NULL) {
      pthread_mutex_lock(&(process->process_lock));
      if (process->allowed_dram > process->current_dram) {
        // process can have more DRAM, so it can migrate things up if it can
        migrate_up_bytes = process->allowed_dram - process->current_dram;
      } else if (process->allowed_dram < process->current_dram) {
        // process has too much dram, so it needs to migrate things down
        migrate_up_bytes = 0;
      } else {
        // process has correct amount of DRAM, migrate up and down
        // an equal number of pages to the process's NVM hot list
        migrate_up_bytes = mig_down_equi;
      }

      // now migrate up to newly freed DRAM space
      process_migrate_up(process, migrate_up_bytes);
      
      process->cur_cool_in_dram = partial_cool(process, true);
      process->cur_cool_in_nvm = partial_cool(process, false);

      tmp = process;
      process = process->next;
      pthread_mutex_unlock(&(tmp->process_lock));
    }

#else
    process = peek_process(&processes_list);
    while (process != NULL) {
      pthread_mutex_lock(&(process->process_lock));
      handle_ring_requests(process);

      if (process->allowed_dram > process->current_dram) {
        // process can have more DRAM, so it can migrate things up if it can
        migrate_up_bytes = process->allowed_dram - process->current_dram;
        migrate_down_bytes = 0;
      } else if (process->allowed_dram < process->current_dram) {
        // process has too much dram, so it needs to migrate things down
        migrate_up_bytes = 0;
        migrate_down_bytes = process->current_dram - process->allowed_dram;
      } else {
        // process has correct amount of DRAM, migrate up and down
        // an equal number of pages to the process's NVM hot list
        migrate_up_bytes = process->nvm_hot_list.numentries * PAGE_SIZE;
        migrate_down_bytes = process->nvm_hot_list.numentries * PAGE_SIZE;
      }

      // migrate down first to free up DRAM space
      process_migrate_down(process, migrate_down_bytes);

      // now migrate up to newly freed DRAM space
      process_migrate_up(process, migrate_up_bytes);
      
      process->cur_cool_in_dram = partial_cool(process, true);
      process->cur_cool_in_nvm = partial_cool(process, false);

      tmp = process;
      process = process->next;
      pthread_mutex_unlock(&(tmp->process_lock));
    }
#endif
    gettimeofday(&end, NULL);
    migrate_time = 1000000 * elapsed(&start, &end);
    if (migrate_time < 1000000.0) {
      usleep((uint64_t)(1000000.0 - migrate_time));
    }
  }

  return NULL;
}

static struct hemem_page* pebs_allocate_page(struct hemem_process* process)
{
  struct timeval start, end;
  struct hemem_page *page;

  gettimeofday(&start, NULL);
  page = dequeue_page(&dram_free_list);
  if (page != NULL) {
    assert(page->in_dram);
    assert(!page->present);

    page->present = true;
    enqueue_page(&(process->dram_lists[COLD]), page);

    gettimeofday(&end, NULL);
    LOG_TIME("mem_policy_allocate_page: %f s\n", elapsed(&start, &end));

    return page;
  }
    
  // DRAM is full, fall back to NVM
  page = dequeue_page(&nvm_free_list);
  if (page != NULL) {
    assert(!page->in_dram);
    assert(!page->present);

    page->present = true;
    enqueue_page(&(process->nvm_lists[COLD]), page);

    gettimeofday(&end, NULL);
    LOG_TIME("mem_policy_allocate_page: %f s\n", elapsed(&start, &end));

    return page;
  }

  assert(!"Out of memory");
}

struct hemem_page* pebs_pagefault(struct hemem_process *process)
{
  struct hemem_page *page;

  // do the heavy lifting of finding the devdax file offset to place the page
  page = pebs_allocate_page(process);
  assert(page != NULL);

  return page;
}

void pebs_remove_page(struct hemem_process *process, struct hemem_page *page)
{
  assert(page != NULL);

  //LOG("pebs: remove page, put this page into free_page_ring: va: 0x%lx\n", page->va);

  while (ring_buf_full(process->free_page_ring));
  pthread_mutex_lock(&(process->free_page_ring_lock));
  ring_buf_put(process->free_page_ring, (uint64_t*)page); 
  pthread_mutex_unlock(&(process->free_page_ring_lock));

}

void pebs_add_process(struct hemem_process *process)
{
#ifdef HEMEM_QOS
  // new process gets to start with the amount of allowed dram
  // equal to the amount of cold dram the processes of lower
  // priority are using
  struct hemem_process *tmp, *tmp1;
  enqueue_process(&processes_list, process);
  pthread_mutex_lock(&(process->process_lock));
  process->current_dram = 0;
  process->allowed_dram = dram_free_list.numentries * PAGE_SIZE;
  tmp = process->next;
  while (tmp != NULL) {
    pthread_mutex_lock(&(tmp->process_lock));
    process->allowed_dram += tmp->dram_lists[COLD].numentries * PAGE_SIZE;
    tmp->allowed_dram -= tmp->dram_lists[COLD].numentries * PAGE_SIZE;
    tmp1 = tmp;
    tmp = tmp->next;
    pthread_mutex_unlock(&(tmp1->process_lock));
  }
  pthread_mutex_unlock(&(process->process_lock));
#else
  // reallocate DRAM among all current processes
  // policy thread will handle migrating up and down
  // the correct number of pages to achieve the
  // allocations the next time it runs
  struct hemem_process *tmp, *tmp1;
  tmp = peek_process(&processes_list);
  while (tmp != NULL) {
    pthread_mutex_lock(&(tmp->process_lock));
    tmp->allowed_dram = DRAMSIZE / (processes_list.numentries + 1);
    tmp1 = tmp;
    tmp = tmp->next;
    pthread_mutex_unlock(&(tmp1->process_lock));
  }
  
  // in non-QOS mode, the lc list just acts like the total process list
  process->current_dram = 0;
  process->allowed_dram = DRAMSIZE / (processes_list.numentries + 1);
  enqueue_process(&processes_list, process);

#endif
}

void pebs_remove_process(struct hemem_process *process)
{
  uint64_t freed_dram;

  process_list_remove(&processes_list, process);
  pthread_mutex_lock(&(process->process_lock));
  freed_dram = process->current_dram;
  process->current_dram = 0;
  process->allowed_dram = 0;
  pthread_mutex_unlock(&(process->process_lock));
  
  // allocate the newly freed dram among all the remaining processes
  // policy thread wil correct actual allocations later
  struct hemem_process *tmp, *tmp1;
  tmp = peek_process(&processes_list);
  while (tmp != NULL) {
    pthread_mutex_lock(&(tmp->process_lock));
    tmp->allowed_dram += (freed_dram / processes_list.numentries);
    tmp1 = tmp;
    tmp = tmp->next;
    pthread_mutex_unlock(&(tmp1->process_lock));
  }
}

void pebs_init(void)
{
  pthread_t kswapd_thread;
  pthread_t scan_thread;
  int ret;

  LOG("pebs_init: started\n");

  for (int i = 4; i < PEBS_NPROCS - 1; i++) {
    perf_page[i][DRAMREAD] = perf_setup(0x1d3, 0, i, DRAMREAD);      // MEM_LOAD_L3_MISS_RETIRED.LOCAL_DRAM
    perf_page[i][NVMREAD] = perf_setup(0x80d1, 0, i, NVMREAD);     // MEM_LOAD_RETIRED.LOCAL_PMM
    //perf_page[i][WRITE] = perf_setup(0x82d0, 0, i, WRITE);    // MEM_INST_RETIRED.ALL_STORES
  }

  pthread_mutex_init(&(dram_free_list.list_lock), NULL);
  for (int i = 0; i < DRAMSIZE / PAGE_SIZE; i++) {
    struct hemem_page *p = calloc(1, sizeof(struct hemem_page));
    p->devdax_offset = i * PAGE_SIZE;
    p->present = false;
    p->in_dram = true;
    p->ring_present = false;
    p->pt = pagesize_to_pt(PAGE_SIZE);

    enqueue_page(&dram_free_list, p);
  }

  pthread_mutex_init(&(nvm_free_list.list_lock), NULL);
  for (int i = 0; i < NVMSIZE / PAGE_SIZE; i++) {
    struct hemem_page *p = calloc(1, sizeof(struct hemem_page));
    p->devdax_offset = i * PAGE_SIZE;
    p->present = false;
    p->in_dram = false;
    p->ring_present = false;
    p->pt = pagesize_to_pt(PAGE_SIZE);

    enqueue_page(&nvm_free_list, p);
  }

  ret = pthread_create(&scan_thread, NULL, pebs_scan_thread, NULL);
  assert(ret == 0);
  
  ret = pthread_create(&kswapd_thread, NULL, pebs_policy_thread, NULL);
  assert(ret == 0);
  
  LOG("Memory management policy is PEBS\n");

  LOG("pebs_init: finished\n");

}

void pebs_shutdown()
{
  for (int i = 0; i < PEBS_NPROCS; i++) {
    for (int j = 0; j < NPBUFTYPES; j++) {
      ioctl(pfd[i][j], PERF_EVENT_IOC_DISABLE, 0);
      //munmap(perf_page[i][j], sysconf(_SC_PAGESIZE) * PERF_PAGES);
    }
  }
}

void count_pages()
{
  struct hemem_process *process, *tmp;
  process = peek_process(&processes_list);
  while (process != NULL) {
    //pthread_mutex_lock(&(process->process_lock));
    for(int i = 0; i < NUM_HOTNESS_LEVELS; i++) {
        dram_pages_count[i] += process->dram_lists[i].numentries;
    }

    for(int i = 0; i < NUM_HOTNESS_LEVELS; i++) {
        nvm_pages_count[i] += process->nvm_lists[i].numentries;
    }

    //tmp = process;
    process = process->next;
    //pthread_mutex_unlock(&(tmp->process_lock));
  }
}

void pebs_stats()
{
  /* TODO: change to per-process
  LOG_STATS("\tdram_hot_list.numentries: [%ld]\tdram_cold_list.numentries: [%ld]\tnvm_hot_list.numentries: [%ld]\tnvm_cold_list.numentries: [%ld]\themem_pages: [%lu]\ttotal_pages: [%lu]\tzero_pages: [%ld]\tthrottle/unthrottle_cnt: [%ld/%ld]\tcools: [%ld]\n",
          dram_hot_list.numentries,
          dram_cold_list.numentries,
          nvm_hot_list.numentries,
          nvm_cold_list.numentries,
          hemem_pages_cnt,
          total_pages_cnt,
          zero_pages_cnt,
          throttle_cnt,
          unthrottle_cnt,
          cools);
  hemem_pages_cnt = total_pages_cnt =  throttle_cnt = unthrottle_cnt = 0;
  */

  count_pages();

  LOG_STATS("\tnum_processes: [%u]\tlc_processes: [%ld]\tstale_candidate_count: [%lu]\tdram_cold: [%lu]\tnvm_hot: [%lu]\tnvm_cold: [%lu]\tdram_free: [%lu]\tnvm_free: [%lu]\n",
        HASH_CNT(phh, processes),
        processes_list.numentries,
        stale_candidate_count,
        0,
        0,
        0,
        dram_free_list.numentries,
        nvm_free_list.numentries);
  LOG_STATS("\themem_pages: [%lu]\tother_pages: [%lu]\tzero_pages: [%ld]\tother_processes: [%ld]\tthrottle/unthrottle: [%ld/%ld]\tcools: [%ld]\n",
        hemem_pages_cnt,
        total_pages_cnt - hemem_pages_cnt,
        zero_pages_cnt,
        other_processes_cnt,
        throttle_cnt,
        unthrottle_cnt,
        cools);
  
  LOG_STATS("dram_lists: [", NULL);
  for(int i = 0; i < NUM_HOTNESS_LEVELS; i++) {
      LOG_STATS("%lu, ", dram_pages_count[i]);
  }
  LOG_STATS("]\n", NULL);

  LOG_STATS("nvm_lists: [", NULL);
  for(int i = 0; i < NUM_HOTNESS_LEVELS; i++) {
      LOG_STATS("%lu, ", nvm_pages_count[i]);
  }
  LOG_STATS("]\n", NULL);

  hemem_pages_cnt = total_pages_cnt = other_processes_cnt = throttle_cnt = unthrottle_cnt = 0;
  for(int i = 0; i < NUM_HOTNESS_LEVELS; i++) {
      dram_pages_count[i] = 0;
      nvm_pages_count[i] = 0;
  }
}

