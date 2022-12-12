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
uint64_t dram_cools = 0, nvm_cools = 0;
uint64_t dram_cools_finished = 0, nvm_cools_finished = 0;
uint64_t stale_candidate_count = 0;

_Atomic volatile uint64_t free_ring_requests = 0;
_Atomic volatile uint64_t hot_ring_requests = 0;
_Atomic volatile uint64_t cold_ring_requests = 0;

_Atomic volatile uint64_t free_ring_requests_handled = 0;
_Atomic volatile uint64_t hot_ring_requests_handled = 0;
_Atomic volatile uint64_t cold_ring_requests_handled = 0;

struct page_list dram_lists[NUM_HOTNESS_LEVELS + 1];
struct page_list nvm_lists[NUM_HOTNESS_LEVELS + 1];
int cur_cool_in_dram_list;
int cur_cool_in_nvm_list;
struct hemem_page *cur_cool_in_dram;
struct hemem_page *cur_cool_in_nvm;
volatile bool need_cool_dram;
volatile bool need_cool_nvm;
volatile ring_handle_t hot_ring;
volatile ring_handle_t cold_ring;
volatile ring_handle_t free_page_ring;
pthread_mutex_t free_page_ring_lock;


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

void make_hot_request(struct hemem_page* page)
{
   page->ring_present = true;
   ring_buf_put(hot_ring, (uint64_t*)page);
   hot_ring_requests++;
}

void make_cold_request(struct hemem_page* page)
{
    page->ring_present = true;
    ring_buf_put(cold_ring, (uint64_t*)page);
    cold_ring_requests++;
}

static inline int access_to_index(uint64_t num) {
  if(num <= 0) {
    return 0;
  }
  int ret = 64 - __builtin_clzll(num);
  if(ret > NUM_HOTNESS_LEVELS - 1) {
    return NUM_HOTNESS_LEVELS - 1;
  }
  return ret;
}

void *pebs_scan_thread()
{
  struct perf_event_mmap_page *p;
  char *pbuf;
  struct perf_event_header *ph;
  struct perf_sample* ps;
  struct hemem_page* page;
  uint64_t total_accesses;
  int new_hotness, i, j, s;

  cpu_set_t cpuset;
  pthread_t thread;

  thread = pthread_self();
  CPU_ZERO(&cpuset);
  CPU_SET(SCANNING_THREAD_CPU, &cpuset);
  s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (s != 0) {
    perror("pthread_setaffinity_np");
    assert(0);
  }

  for(;;) {
    for (i = LAST_HEMEM_THREAD + 1; i < PEBS_NPROCS - 1; i++) {
      for(j = 0; j < NPBUFTYPES; j++) {
        p = perf_page[i][j];
        pbuf = (char *)p + p->data_offset;

        __sync_synchronize();

        if(p->data_head == p->data_tail) {
          continue;
        }

        ph = (void *)(pbuf + (p->data_tail % p->data_size));

        switch(ph->type) {
        case PERF_RECORD_SAMPLE:
            ps = (struct perf_sample*)ph;
            assert(ps != NULL);
            if(ps->addr != 0) {
              __u64 pfn = ps->addr & HUGE_PFN_MASK;
              page = find_page(pfn, ps->pid);

              if (page != NULL) {
                if (page->va != 0) {
                  page->accesses[j]++;
                  page->tot_accesses[j]++;
                    
                  total_accesses = page->accesses[DRAMREAD] + page->accesses[NVMREAD];
                  new_hotness = access_to_index(total_accesses);
                  // check for hotness change and add to ring
                  if(new_hotness > page->hot) {
                    make_hot_request(page);
                  }
                  else if(new_hotness < page->hot) {
                    make_cold_request(page);
                  }

                  page->accesses[DRAMREAD] >>= (global_clock - page->local_clock);
                  page->accesses[NVMREAD] >>= (global_clock - page->local_clock);
                  page->local_clock = global_clock;
                  if (page->accesses[j] > PEBS_COOLING_THRESHOLD) {
                    global_clock++;
                    dram_cools++;
                    nvm_cools++;
                    need_cool_dram = true;
                    need_cool_nvm = true;
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

static void pebs_migrate_down(struct hemem_page *page, uint64_t offset)
{
  struct timeval start, end;

  if (!can_migrate_page(page->pid)) {
    remove_page(page);
    pebs_remove_page(page);
    return;
  }

  gettimeofday(&start, NULL);

  page->migrating = true;
  hemem_ucm_wp_page(page, true);
  hemem_ucm_migrate_down(page, offset);
  page->migrating = false; 

  gettimeofday(&end, NULL);
  LOG_TIME("migrate_down: %f s\n", elapsed(&start, &end));
}

static void pebs_migrate_up(struct hemem_page *page, uint64_t offset)
{
  struct timeval start, end;
  
  if (!can_migrate_page(page->pid)) {
    remove_page(page);
    pebs_remove_page(page);
    return;
  }

  gettimeofday(&start, NULL);

  page->migrating = true;
  hemem_ucm_wp_page(page, true);
  hemem_ucm_migrate_up(page, offset);
  page->migrating = false;

  gettimeofday(&end, NULL);
  LOG_TIME("migrate_up: %f s\n", elapsed(&start, &end));
}

// moves page to hot list -- called by migrate thread
void make_hot(struct hemem_page* page, int new_hot)
{
  assert(page != NULL);
  assert(page->va != 0);

  if (page->hot == new_hot) {
    if (page->in_dram) {
      assert(page->list == &(dram_lists[new_hot]));
    }
    else {
      assert(page->list == &(nvm_lists[new_hot]));
    }

    return;
  }

  if (page->in_dram) {
    assert(page->list == &(dram_lists[page->hot]));
    page_list_remove(&(dram_lists[page->hot]), page);
    page->hot = new_hot;
    enqueue_page(&(dram_lists[page->hot]), page);
  }
  else {
    assert(page->list == &(nvm_lists[page->hot]));
    page_list_remove(&(nvm_lists[page->hot]), page);
    page->hot = new_hot;
    enqueue_page(&(nvm_lists[page->hot]), page);
  }
}

// moves page to cold list -- called by migrate thread
void make_cold(struct hemem_page* page, int new_hot)
{
  assert(page != NULL);
  assert(page->va != 0);

  if (page->hot == new_hot) {
    if (page->in_dram) {
      assert(page->list == &(dram_lists[new_hot]));
    }
    else {
      assert(page->list == &(nvm_lists[new_hot]));
    }

    return;
  }

  if (page->in_dram) {
    assert(page->list == &(dram_lists[page->hot]));
    page_list_remove(&(dram_lists[page->hot]), page);
    page->hot = new_hot;
    enqueue_page(&(dram_lists[new_hot]), page);
  }
  else {
    assert(page->list == &(nvm_lists[page->hot]));
    page_list_remove(&(nvm_lists[page->hot]), page);
    page->hot = new_hot;
    enqueue_page(&(nvm_lists[page->hot]), page);
  }
}

struct hemem_page* partial_cool(bool dram)
{
  struct hemem_page *p, *current;
  uint64_t tmp_accesses[NPBUFTYPES];
  int cool_list, cur_list_index;
  bool goto_next_list = false;
  struct page_list* cur_bins;
  int i, j, new_hotness;

  struct timeval start, end;

  // do we even need to be cooling right now? If not, just return
  // where we left off last time we needed to cool. Next time this function
  // is called when cooling is needed, we pick up from here
  if (dram && !need_cool_dram) {
    return cur_cool_in_dram;
  } else if (!dram && !need_cool_nvm) {
    return cur_cool_in_nvm;
  }

  // we cool backwards through the page lists, the same order the pages
  // were inserted. The idea is, in this way, we cool the oldest pages first
  if (dram && (cur_cool_in_dram == NULL) && (cur_cool_in_dram_list == 0)) {
    for (i = NUM_HOTNESS_LEVELS-1; i > 0 && cur_cool_in_dram == NULL; i--) {
      // find the current oldest hottest page in DRAM
      cur_cool_in_dram = dram_lists[i].last;
      cur_cool_in_dram_list = i;
    }
    // dram hot list might be empty, in which case we have nothing to cool
    if (cur_cool_in_dram == NULL) {
      cur_cool_in_dram_list = 0;
      need_cool_dram = false;
      dram_cools_finished++;
      return NULL;
    }
  } else if ((!dram) && (cur_cool_in_nvm == NULL) && (cur_cool_in_nvm_list == 0)) {
    for (int i = NUM_HOTNESS_LEVELS-1; i > 0 && cur_cool_in_nvm == NULL; i--) {
      // find the current oldest hottest page in NVM
      cur_cool_in_nvm = nvm_lists[i].last;
      cur_cool_in_nvm_list = i;
    }
    // nvm hot list might be empty, in which case we have nothing to cool
    if (cur_cool_in_nvm == NULL) {
      cur_cool_in_nvm_list = 0;
      need_cool_nvm = false;
      nvm_cools_finished++;
      return NULL;
    }
  }

  gettimeofday(&start, NULL);

  // set hot and cold list pointers as appropriate for memory type
  // set current to the current cooled page for the memory type here as well
  if (dram) {
    current = cur_cool_in_dram;
    cool_list = cur_cool_in_dram_list;
    cur_bins = dram_lists;
    if (current) {
      assert(current->list == &(cur_bins[current->hot]));
    }
  } else {
    current = cur_cool_in_nvm;
    cool_list = cur_cool_in_nvm_list;
    cur_bins = nvm_lists;
    if (current) {
      assert(current->list == &(cur_bins[current->hot]));
    }
  }
  
  // start from the current cooled page. This is either where we left off
  // last time or the end of the page list if we've gone throug the whole list
  p = current;
  cur_list_index = cool_list;
  for (i = 0; i < COOLING_PAGES; i++) {
    if (p == NULL) {
      // not pointing to a page to cool from. check the lower lists. 
      for (j = cool_list; j > 0 && p == NULL; j--) {
        p = cur_bins[j].last;
        cool_list = j;
      }
      if (p == NULL) {
        cool_list = 0;
        break;
      }
    }

    // sanity check we grabbed a page in the appropriate memory type and
    // from the appropriate list
    if (dram) {
        assert(p->in_dram);
        assert(p->list == &(dram_lists[p->hot]));
    } else {
        assert(!p->in_dram);
        assert(p->list == &(nvm_lists[p->hot]));
    }

    // compute the access samples this page would have had if it were up to date
    // with cooling
    for (int j = 0; j < NPBUFTYPES; j++) {
        tmp_accesses[j] = p->accesses[j] >> (global_clock - p->local_clock);
    }

    // is the page still hot if it was up to date with cooling?
    new_hotness = access_to_index(tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD]);
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
    } else {
      current = p;
      cur_list_index = cool_list;
    }
    
    // have we gone through the entire hot list? If so, call for the 
    // loop iteration to goto the next list.
    if (dram && (p == dram_lists[cool_list].first)) {
      goto_next_list = true;
    } else if (!dram && (p == nvm_lists[cool_list].first)) {
      goto_next_list = true;
    } 

    // grab another page to cool
    // first if we need to goto next list then goto that list for the next.
    if(goto_next_list) {
      if(cool_list == 1) {
        // we've cooled everything thre is to cool
        cur_list_index = 0;
        current = NULL;
        if (dram) {
          need_cool_dram = false;
          dram_cools_finished++;
        } else {
          need_cool_nvm = false;
          nvm_cools_finished++;
        }
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

  if (dram) {
    cur_cool_in_dram_list = cur_list_index;
  }
  else {
    cur_cool_in_nvm_list = cur_list_index;
  }

  gettimeofday(&end, NULL);
  LOG_TIME("partial_cool: %f s\n", elapsed(&start, &end));

  return current;
}

// convenience function for catching pages where we migrate or otherwise move a page
// from one list to another. If the page in question was our "bookmark" pointer for
// cooling, then we need to update that bookmark. Here, for simplicity, we just
// reset our bookmark to the end of the hot list
void update_current_cool_page(struct hemem_page *page)
{
  if (page == cur_cool_in_dram) {
    // first a set of sanity checks
    assert(page->in_dram);
    assert(page->list == &(dram_lists[page->hot]));
    // then just reset the bookmark pointer to the last page in list
    // just restart
    cur_cool_in_dram = NULL;
    cur_cool_in_dram_list = 0;
  } else if (page == cur_cool_in_nvm) {
    // first, a bunch of sanity checks
    assert(!(page->in_dram));
    assert(page->list == &(nvm_lists[page->hot]));
    // then just reset the bookmark pointer to the last page in list
    cur_cool_in_nvm = NULL;
    cur_cool_in_nvm_list = 0;
  }
}


// The PEBS thread communicates with the policy thread via request rings. The
// only thread allowed to maniuplate the hot and cold lists is the policy thread
// to prevent deadlocks or race conditions, and the ring buffers solve that.
// Here, the policy thread will handle the ring buffer requests by placing
// the pages in the ring buffers into the appropriate lists
void handle_ring_requests()
{
  int num_ring_reqs;
  struct hemem_page* page = NULL;
  uint64_t tmp_accesses[NPBUFTYPES];
  int new_hotness;

  // free pages using free page ring buffer
  // we take all pages from the free ring rather than until
  // meeting some threshold of requests handled to free up
  // as much space as quick as possible
  while(!ring_buf_empty(free_page_ring)) {
    struct page_list *list;
    pthread_mutex_lock(&(free_page_ring_lock));
    page = (struct hemem_page*)ring_buf_get(free_page_ring);
    pthread_mutex_unlock(&(free_page_ring_lock));
    if (page == NULL) {
      // ring buffer was empty
      break;
    }
        
    list = page->list;
    assert(list != NULL);

    // list sanity checks
    // either in the correct list or in a ring. 
#if 0 //bug here, disable it for now
    if (page->in_dram) {
      assert(page->list == &(dram_lists[page->hot]) || page->ring_present);
    } else {
      assert(page->list == &(nvm_lists[page->hot]) || page->ring_present);
    } 
#endif 

    // check whether the page being freed is our bookmark cool page
    update_current_cool_page(page);
    
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
    free_ring_requests_handled++;
  }

  page = NULL;
  num_ring_reqs = 0;
  // handle hot requests from hot buffer by moving pages to hot list
  while(!ring_buf_empty(hot_ring) && num_ring_reqs < HOT_RING_REQS_THRESHOLD) {
	  page = (struct hemem_page*)ring_buf_get(hot_ring);
    if (page == NULL) {
      // ring buffer was empty
      break;
    }

    if (!page->present) {
      // page has been freed
      if (page->in_dram) {
        assert(page->list == &dram_free_list);
      } else {
        assert(page->list == &nvm_free_list);
      }
      hot_ring_requests_handled++;
      continue;
    }
    
    // compute the access samples this page would have had if it were up to date
    // with cooling
    for (int j = 0; j < NPBUFTYPES; j++) {
        tmp_accesses[j] = page->accesses[j] >> (global_clock - page->local_clock);
    }
    new_hotness = access_to_index(tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD]);
   
    // is page even still hot?
    if (new_hotness < page->hot) {
      // page has been cooled and is no longer hot, just move to cold list
      // first, check to see if we need to update our cooling bookmark
      update_current_cool_page(page);
      page->ring_present = false;
      num_ring_reqs++;
      make_cold(page, new_hotness);
      hot_ring_requests_handled++;
      continue;
    }

    // page is still hot, so we can move it to the hot list
    // do we need to update our cooling bookmark?
    update_current_cool_page(page);
    page->ring_present = false;
    num_ring_reqs++;
    make_hot(page, new_hotness);
    //printf("hot ring, hot pages:%llu\n", num_ring_reqs);
    
    hot_ring_requests_handled++;
  }

  page = NULL;
  num_ring_reqs = 0;
  // handle cold requests from cold buffer by moving pages to cold list
  while(!ring_buf_empty(cold_ring) && num_ring_reqs < COLD_RING_REQS_THRESHOLD) {
    page = (struct hemem_page*)ring_buf_get(cold_ring);
    if (page == NULL) {
      // ring buffer was empty
      break;
    }

    if (!page->present) {
      // page has been freed
      if (page->in_dram) {
        assert(page->list == &dram_free_list);
      } else {
        assert(page->list == &nvm_free_list);
      }
      cold_ring_requests_handled++;
      continue;
    }
    
    // compute the access samples this page would have had if it were up to date
    // with cooling
    for (int j = 0; j < NPBUFTYPES; j++) {
        tmp_accesses[j] = page->accesses[j] >> (global_clock - page->local_clock);
    }
    new_hotness = access_to_index(tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD]);

    if (new_hotness >= page->hot) {
      // page is now hot and should actually move to the hot list
      // if not already there
      update_current_cool_page(page);
      page->ring_present = false;
      num_ring_reqs++;
      make_hot(page, new_hotness);
      cold_ring_requests_handled++;
      continue;
    }

    // check if we need to update our cooling bookmark, then move page
    // to the cold list
    update_current_cool_page(page);
    page->ring_present = false;
    num_ring_reqs++;
    make_cold(page, new_hotness);
    //printf("cold ring, cold pages:%llu\n", num_ring_reqs);
    cold_ring_requests_handled++;
  }
}

struct hemem_page* find_candidate_nvm_page() {
  struct hemem_page* p;

  for(int i = NUM_HOTNESS_LEVELS-1; i >= 0; i--) {
    p = dequeue_page(&(nvm_lists[i]));

    if (p != NULL) {
      // found something hot. we should try to promote it.
      return p;
    }
  }
  return NULL;
}

struct hemem_page* find_dram_victim(int64_t max_hotness) {
  struct hemem_page* p;
  for(int i = max_hotness-1; i >= 0; i--) {
    p = (struct hemem_page*)dequeue_page(&(dram_lists[i]));
    if (p != NULL) {
      // found something cold. we should try to evict it.
      return p;
    }
  }
  return NULL;
}

void *pebs_policy_thread()
{
  cpu_set_t cpuset;
  pthread_t thread;
  int tries;
  struct hemem_page *p;
  struct hemem_page *cp;
  struct hemem_page *np;
  uint64_t migrated_bytes;
  uint64_t old_offset;
  int ret;
  struct timeval start, end;
  double migrate_time;

  thread = pthread_self();
  CPU_ZERO(&cpuset);
  CPU_SET(POLICY_THREAD_CPU, &cpuset);
  ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (ret != 0) {
    perror("pthread_setaffinity_np");
    assert(0);
  }

  for (;;) {
    gettimeofday(&start, NULL);

    handle_ring_requests();

    // move each hot NVM page to DRAM
    for (migrated_bytes = 0; migrated_bytes < PEBS_MIGRATE_RATE;) {
      p = find_candidate_nvm_page();
      if(p == NULL) {
        // didn't find hot page to move up. bail.
        break;
      }

      update_current_cool_page(p);

      if (access_to_index(p->accesses[DRAMREAD] + p->accesses[NVMREAD]) < p->hot) {
        // it has been cooled, need to move it into the cold list
        p->hot = access_to_index(p->accesses[DRAMREAD] + p->accesses[NVMREAD]);
        enqueue_page(&nvm_lists[p->hot], p);
        continue;
      }

      for (tries = 0; tries < 2; tries++) {
        // find a free DRAM page
        np = dequeue_page(&dram_free_list);

        if (np != NULL) {
          assert(!(np->present));

          update_current_cool_page(np);

          old_offset = p->devdax_offset;
          pebs_migrate_up(p, np->devdax_offset);
          np->devdax_offset = old_offset;
          np->in_dram = false;
          np->present = false;
          np->hot = 0;
          for (int i = 0; i < NPBUFTYPES; i++) {
            np->accesses[i] = 0;
            np->tot_accesses[i] = 0;
          }

          enqueue_page(&(dram_lists[p->hot]), p);
          enqueue_page(&nvm_free_list, np);

          migrated_bytes += pt_to_pagesize(p->pt);
          break;
        }

        // no free dram page, try to find a cold dram page to move down
        cp = find_dram_victim(p->hot);
        if(cp == NULL) {
          // no victim
          enqueue_page(&nvm_lists[p->hot], p);
          goto out;
        }
        assert(cp != NULL);

        update_current_cool_page(cp);

        // find a free nvm page to move the cold dram page to
        np = dequeue_page(&nvm_free_list);
        if (np != NULL) {
          assert(!(np->present));

          update_current_cool_page(np);

          old_offset = cp->devdax_offset;
          pebs_migrate_down(cp, np->devdax_offset);
          np->devdax_offset = old_offset;
          np->in_dram = true;
          np->present = false;
          np->hot = 0;
          for (int i = 0; i < NPBUFTYPES; i++) {
            np->accesses[i] = 0;
            np->tot_accesses[i] = 0;
          }

          // move it and try again I guess
          enqueue_page(&nvm_lists[cp->hot], cp);
          enqueue_page(&dram_free_list, np);
        }
        assert(np != NULL);
      }
    }

    cur_cool_in_dram = partial_cool(true);
    cur_cool_in_nvm = partial_cool(false);

out:
    gettimeofday(&end, NULL);
    migrate_time = PEBS_POLICY_INTERVAL * elapsed(&start, &end);
    if (migrate_time < (1.0 * PEBS_POLICY_INTERVAL)) {
      usleep((uint64_t)((1.0 * PEBS_POLICY_INTERVAL) - migrate_time));
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
    
    enqueue_page(&(dram_lists[COLD]), page);

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
    enqueue_page(&(nvm_lists[COLD]), page);

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

void pebs_remove_page(struct hemem_page *page)
{
  assert(page != NULL);

  //LOG("pebs: remove page, put this page into free_page_ring: va: 0x%lx\n", page->va);

  while (ring_buf_full(free_page_ring));
  pthread_mutex_lock(&free_page_ring_lock);
  ring_buf_put(free_page_ring, (uint64_t*)page); 
  free_ring_requests++;
  pthread_mutex_unlock(&free_page_ring_lock);

  page->present = false;
  page->hot = false;

  for (int i = 0; i < NPBUFTYPES; i++) {
    page->accesses[i] = 0;
    page->tot_accesses[i] = 0;
  }

}

void pebs_init(void)
{
  pthread_t kswapd_thread;
  pthread_t scan_thread;
  int ret;

  LOG("pebs_init: started\n");

  for (int i = LAST_HEMEM_THREAD + 1; i < PEBS_NPROCS - 1; i++) {
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

  LOG_STATS("\tnum_processes: [%lu]\tdram_free: [%lu]\tnvm_free: [%lu]\thot_ring: [%lu]\thot_handled: [%ld]\tcold_ring: [%ld]\tcold_handled: [%ld]\tfree_ring: [%ld]\tfree_handled: [%ld]\tstale_candidates: [%ld]\n",
        processes_list.numentries,
        dram_free_list.numentries,
        nvm_free_list.numentries,
        hot_ring_requests,
        hot_ring_requests_handled,
        cold_ring_requests,
        cold_ring_requests_handled,
        free_ring_requests,
        free_ring_requests_handled,
        stale_candidate_count);
  LOG_STATS("\themem_pages: [%lu]\tother_pages: [%lu]\tzero_pages: [%ld]\tother_processes: [%ld]\tthrottle/unthrottle: [%ld/%ld]\tcools: [%ld/%ld]\tcools_finished: [%ld/%ld]\n",
        hemem_pages_cnt,
        total_pages_cnt - hemem_pages_cnt,
        zero_pages_cnt,
        other_processes_cnt,
        throttle_cnt,
        unthrottle_cnt,
        dram_cools,
        nvm_cools,
        dram_cools_finished,
        nvm_cools_finished);
  hemem_pages_cnt = total_pages_cnt = other_processes_cnt = throttle_cnt = unthrottle_cnt = 0;
}

