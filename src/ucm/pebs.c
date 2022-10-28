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

static struct process_list lc_list, be_list;

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
_Atomic uint64_t dram_hot_pages = 0;
_Atomic uint64_t dram_cold_pages = 0;
_Atomic uint64_t nvm_hot_pages = 0;
_Atomic uint64_t nvm_cold_pages = 0;

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

  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_WEIGHT | PERF_SAMPLE_ADDR;
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
    for (int i = 0; i < PEBS_NPROCS; i++) {
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
                    process->accessed_pages[j]++;
                    page->accesses[j]++;
                    page->tot_accesses[j]++;
                    if ((page->accesses[DRAMREAD] + page->accesses[NVMREAD]) >= HOT_READ_THRESHOLD) {
                      if (!page->hot && !page->ring_present) {
                        make_hot_request(process, page);
                      }
                    }
                    else if ((page->accesses[DRAMREAD] + page->accesses[NVMREAD]) < HOT_READ_THRESHOLD) {
                      if (page->hot && !page->ring_present) {
                        make_cold_request(process, page);
                      }
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
void make_hot(struct hemem_process* process, struct hemem_page* page)
{
  assert(page != NULL);
  assert(page->va != 0);

  if (page->hot) {
    if (page->in_dram) {
      assert(page->list == &(process->dram_hot_list));
    }
    else {
      assert(page->list == &(process->nvm_hot_list));
    }

    return;
  }

  if (page->in_dram) {
    assert(page->list == &(process->dram_cold_list));
    page_list_remove(&(process->dram_cold_list), page);
    dram_cold_pages--;
    page->hot = true;
    enqueue_page(&(process->dram_hot_list), page);
    dram_hot_pages++;
  }
  else {
    assert(page->list == &(process->nvm_cold_list));
    page_list_remove(&(process->nvm_cold_list), page);
    nvm_cold_pages--;
    page->hot = true;
    enqueue_page(&(process->nvm_hot_list), page);
    nvm_hot_pages++;
  }
}

// moves page to cold list -- called by migrate thread
void make_cold(struct hemem_process* process, struct hemem_page* page)
{
  assert(page != NULL);
  assert(page->va != 0);

  if (!page->hot) {
    if (page->in_dram) {
      assert(page->list == &(process->dram_cold_list));
    }
    else {
      assert(page->list == &(process->nvm_cold_list));
    }

    return;
  }

  if (page->in_dram) {
    assert(page->list == &(process->dram_hot_list));
    page_list_remove(&(process->dram_hot_list), page);
    dram_hot_pages--;
    page->hot = false;
    enqueue_page(&(process->dram_cold_list), page);
    dram_cold_pages++;
  }
  else {
    assert(page->list == &(process->nvm_hot_list));
    page_list_remove(&(process->nvm_hot_list), page);
    nvm_hot_pages--;
    page->hot = false;
    enqueue_page(&(process->nvm_cold_list), page);
    nvm_cold_pages++;
  }
}

struct hemem_page* partial_cool(struct hemem_process* process, bool dram)
{
  struct hemem_page *p, *current;
  uint64_t tmp_accesses[NPBUFTYPES];
  struct page_list* hot;
  struct page_list* cold;

  // do we even need to be cooling right now? If not, just return
  // where we left off last time we needed to cool. Next time this function
  // is called when cooling is needed, we pick up from here
  if (dram && !(process->need_cool)) {
    return process->cur_cool_in_dram;
  } else if (!dram && !(process->need_cool)) {
    return process->cur_cool_in_nvm;
  }

  // we cool backwards through the page lists, the same order the pages
  // were inserted. The idea is, in this way, we cool the oldest pages first
  if (dram && (process->cur_cool_in_dram == NULL)) {
      process->cur_cool_in_dram = process->dram_hot_list.last;
      // dram hot list might be empty, in which case we have nothing to cool
      if (process->cur_cool_in_dram == NULL) {
        return NULL;
      }
  } else if ((!dram) && (process->cur_cool_in_nvm == NULL)) {
      process->cur_cool_in_nvm = process->nvm_hot_list.last;
      // nvm hot list might be empty, in which case we have nothing to cool
      if (process->cur_cool_in_nvm == NULL) {
        return NULL;
      }
  }

  // set hot and cold list pointers as appropriate for memory type
  // set current to the current cooled page for the memory type here as well
  if (dram) {
    hot = &(process->dram_hot_list);
    cold = &(process->dram_cold_list);
    current = process->cur_cool_in_dram;
    assert(process->cur_cool_in_dram->list == &(process->dram_hot_list));
  } else {
    hot = &(process->nvm_hot_list);
    cold = &(process->nvm_cold_list);
    current = process->cur_cool_in_nvm;
    assert(process->cur_cool_in_nvm->list == &(process->nvm_hot_list));
  }
  
  // start from the current cooled page. This is either where we left off
  // last time or the end of the page list if we've gone throug the whole list
  p = current;
  for (int i = 0; i < COOLING_PAGES; i++) {
    if (p == NULL) {
        // nothing to cool, just exit
        // likely we've reached the front of the list
        break;
    }

    // sanity check we grabbed a page in the appropriate memory type and
    // from the appropriate list
    if (dram) {
        assert(p->in_dram);
        assert(p->list == &(process->dram_hot_list));
    } else {
        assert(!p->in_dram);
        assert(p->list == &(process->nvm_hot_list));
    }

    // compute the access samples this page would have had if it were up to date
    // with cooling
    for (int j = 0; j < NPBUFTYPES; j++) {
        tmp_accesses[j] = p->accesses[j] >> (global_clock - p->local_clock);
    }

    // is the page still hot if it was up to date with cooling?
    if ((tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD]) < HOT_READ_THRESHOLD) {
        p->hot = false;
    }
    
    // if the page is no longer hot, then we move it to the cold list
    if (!p->hot) {
        // first, we update our current pointer in prep for p being
        // moved to the cold list. This ensures our next call to
        // prev_page() stays in the appropriate list
        current = p->next;
        page_list_remove(hot, p);
        if (dram) dram_hot_pages--;
        else nvm_hot_pages--;
        enqueue_page(cold, p);
        if (dram) dram_cold_pages++;
        else nvm_cold_pages++;
    }
    else {
        // if our page is still hot, then update our current pointer
        current = p;
    }
    
    // have we gone through the entire hot list? If so, set the current cool
    // page to NULL to signify that we do not have a current page to cool and
    // set the needs cooling flag to false for the same reason
    if (dram && (p == process->dram_hot_list.first)) {
        process->need_cool = false;
        return NULL;
    } else if (!dram && (p == process->nvm_hot_list.first)) {
        process->need_cool = false;
        return NULL;
    } 

    // grab another page to cool
    p = prev_page(hot, current);
  }

  return current;
}

// convenience function for catching pages where we migrate or otherwise move a page
// from one list to another. If the page in question was our "bookmark" pointer for
// cooling, the nwe need to update that bookmark. Here, for simplicity, we just
// reset our bookmark to the end of the hot list
void update_current_cool_page(struct hemem_process *process, struct hemem_page *page)
{
  if (page == process->cur_cool_in_dram) {
    // first a set of sanity checks
    assert(page->in_dram);
    assert(page->list == &(process->dram_hot_list));
    // then just reset the bookmark pointer to the last page in list
    process->cur_cool_in_dram = process->dram_hot_list.last;
  } else if (page == process->cur_cool_in_nvm) {
    // first, a bunch of sanity checks
    assert(!(page->in_dram));
    assert(page->list == &(process->nvm_hot_list));
    // then just reset the bookmark pointer to the last page in list
    process->cur_cool_in_nvm = process->nvm_hot_list.last;
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
    if (page->in_dram) {
      if (page->hot) assert(page->list == &(process->dram_hot_list));
      else assert(page->list == &(process->dram_cold_list));
    } else {
      if (page->hot) assert(page->list == &(process->nvm_hot_list));
      else assert(page->list == &(process->nvm_cold_list));
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
      if (page->hot) dram_hot_pages--;
      else dram_cold_pages--;  
      enqueue_page(&dram_free_list, page);
    }
    else {
      if (page->hot) nvm_hot_pages--;
      else nvm_cold_pages--;
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
   
    // is page even still hot?
    if ((tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD]) < HOT_READ_THRESHOLD) {
      // page has been cooled and is no longer hot, just move to cold list
      // first, check to see if we need to update our cooling bookmark
      update_current_cool_page(process, page);
      page->ring_present = false;
      num_ring_reqs++;
      make_cold(process, page);
      continue;
    }

    // page is still hot, so we can move it to the hot list
    // do we need to update our cooling bookmark?
    update_current_cool_page(process, page);
    page->ring_present = false;
    num_ring_reqs++;
    make_hot(process, page);
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

    if ((tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD]) >= HOT_READ_THRESHOLD) {
      // page is now hot and should actually move to the hot list
      // if not already there
      update_current_cool_page(process, page);
      page->ring_present = false;
      num_ring_reqs++;
      make_hot(process, page);
      continue;
    }

    // check if we need to update our cooling bookmark, then move page
    // to the cold list
    update_current_cool_page(process, page);
    page->ring_present = false;
    num_ring_reqs++;
    make_cold(process, page);
    //printf("cold ring, cold pages:%llu\n", num_ring_reqs);
  }
}


// calculate the DRAM load -- that is, the amount of DRAM the latency critical processes need
// in order to have their entire hot sets in DRAM
uint64_t calc_dram_load()
{
  uint64_t dram_load = 0;
  struct hemem_process *process;

  pthread_mutex_lock(&(lc_list.list_lock));
  process = lc_list.first;
  for (int i = 0; i < lc_list.numentries; i++) {
    dram_load += process->nvm_hot_list.numentries * PAGE_SIZE + process->dram_hot_list.numentries * PAGE_SIZE;
    process = process->next;
  }
  pthread_mutex_unlock(&(lc_list.list_lock));
  return dram_load;
}

static inline double calc_miss_ratio(struct hemem_process *process)
{
  return ((1.0 * process->accessed_pages[NVMREAD]) / (process->accessed_pages[DRAMREAD] + process->accessed_pages[NVMREAD]));
}

void take_dram_from_be(uint64_t dram_needed)
{
  struct hemem_process *process;
  uint64_t dram_portion;

  pthread_mutex_lock(&(be_list.list_lock));
  if (be_list.numentries == 0) {
    pthread_mutex_unlock(&(be_list.list_lock));
    return;
  }
  dram_portion = dram_needed / be_list.numentries;
  process = be_list.first;
  for (int i = 0; i < lc_list.numentries; i++) {
    process->migrate_up_bytes += 0;
    process->migrate_down_bytes += dram_portion;
    process = process->next;
  }
  pthread_mutex_unlock(&(be_list.list_lock));
}

void give_dram_to_be(uint64_t dram_needed)
{
  struct hemem_process *process;
  uint64_t dram_portion;

  pthread_mutex_lock(&(be_list.list_lock));
  if (be_list.numentries == 0) {
    pthread_mutex_unlock(&(be_list.list_lock));
    return;
  }
  dram_portion = dram_needed / be_list.numentries;
  process = be_list.first;
  for (int i = 0; i < lc_list.numentries; i++) {
    process->migrate_up_bytes += dram_portion;
    process->migrate_down_bytes += 0;
    process = process->next;
  }
  pthread_mutex_unlock(&(be_list.list_lock));
}

void *pebs_policy_thread()
{
  cpu_set_t cpuset;
  pthread_t thread;
  struct hemem_page *p;
  struct hemem_page *cp;
  struct hemem_page *np;
  uint64_t old_offset;
  uint64_t migrated_bytes;
  uint64_t tmp_accesses[NPBUFTYPES];
  uint64_t dram_needed;
  int ret, i;;
  double real_miss_ratio;
  double dram_load;
  double slack;

  thread = pthread_self();
  CPU_ZERO(&cpuset);
  CPU_SET(MIGRATION_THREAD_CPU, &cpuset);
  ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (ret != 0) {
    perror("pthread_setaffinity_np");
    assert(0);
  }

  for (;;) {
    dram_needed = 0;
    struct hemem_process *process, *tmp;
    
    
    HASH_ITER(phh, processes, process, tmp) {
      // first, handle the ring requests and place pages into appropriate lists
      handle_ring_requests(process);
    }
    
    dram_load = (1.0 * calc_dram_load()) / (1.0 * DRAMSIZE);

    pthread_mutex_lock(&(lc_list.list_lock));
    process = lc_list.first;
    for (i = 0; i < lc_list.numentries; i++) {
      if (process->accessed_pages[DRAMREAD] + process->accessed_pages[NVMREAD] == 0) {
        // no access information from this process since the last policy thread run
        // don't do anything for this process in this case; likely it is allocating
        // some memory and we don't really want to be moving its  pages around in
        // that case anyway. Plus, we avoid dividing by zero below which is always
        // good
        process->migrate_up_bytes = 0;
        process->migrate_down_bytes = 0;
        process = process->next;
        continue;
      }

      // next, calculate how many bytes to migrate up and down based on our
      // target and real miss ratios
      real_miss_ratio = calc_miss_ratio(process);
      process->accessed_pages[DRAMREAD] = process->accessed_pages[NVMREAD] = 0;

      slack = (process->target_miss_ratio - real_miss_ratio) / process->target_miss_ratio; 

      if (slack < 0) {
        // take dram from BE processes
        fprintf(stderr, "slack < 0\n");
        process->migrate_up_bytes = PEBS_MIGRATE_UP_RATE;
        process->migrate_down_bytes = 0;
        dram_needed = PEBS_MIGRATE_UP_RATE;
        take_dram_from_be(dram_needed);
      } else if (dram_load > 0.85) {
        fprintf(stderr, "dram_load > 0.85\n");
        process->migrate_up_bytes = PEBS_MIGRATE_UP_RATE;
        process->migrate_down_bytes = 0;
        // take DRAM from BE processes
        dram_needed = PEBS_MIGRATE_UP_RATE;
        take_dram_from_be(dram_needed);
      } else if (dram_load < 0.80) {
        fprintf(stderr, "dram_load < 0.80\n");
        // can give some DRAM to BE processes
        process->migrate_up_bytes = process->nvm_hot_list.numentries * PAGE_SIZE;
        process->migrate_down_bytes = PEBS_MIGRATE_DOWN_RATE;
        dram_needed = PEBS_MIGRATE_DOWN_RATE;
        give_dram_to_be(dram_needed);
      } else if (slack < 0.10) {
        fprintf(stderr, "slack < 0.10\n");
        process->migrate_up_bytes = process->nvm_hot_list.numentries * PAGE_SIZE;
        process->migrate_down_bytes = process->nvm_hot_list.numentries * PAGE_SIZE;
        // keep BE DRAM shares constant
        if (slack < 0.05) {
          fprintf(stderr, "slack < 0.05\n");
          // take DRAM from BE processes
          process->migrate_up_bytes = process->nvm_hot_list.numentries * PAGE_SIZE;
          process->migrate_down_bytes = (process->nvm_hot_list.numentries * PAGE_SIZE) / 2;
          dram_needed = PEBS_MIGRATE_UP_RATE;
          take_dram_from_be(dram_needed);
        }
      }
      process = process->next;
    }
    pthread_mutex_unlock(&(lc_list.list_lock));


    HASH_ITER(phh, processes, process, tmp) {
      // migrate down first to free up DRAM space
      for (migrated_bytes = 0; migrated_bytes < process->migrate_down_bytes;) {
        if (migrated_bytes >= PEBS_MIGRATE_DOWN_RATE) {
          break;
        }
        cp = dequeue_page(&(process->dram_cold_list));
        if (cp == NULL) {
          // no cold pages to move down -- are we a BE task?
          if (process->priority == BESTEFFORT) {
            // if BE task, choose a random dram hot page to move down
            cp = dequeue_page(&(process->dram_hot_list));
            if (cp == NULL) {
              // BE process has no pages in DRAM, so just break and try again
              break;
            }
          }
          break;
        }
        dram_cold_pages--;

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

          enqueue_page(&(process->nvm_cold_list), cp);
          nvm_cold_pages++;
          enqueue_page(&dram_free_list, np);
          migrated_bytes += pt_to_pagesize(cp->pt);
        } else {
          // no free NVM pages to move, so put it back into
          // dram cold list and bail out
          enqueue_page(&(process->dram_cold_list), cp);
          dram_cold_pages++;
          break;
        }
        //assert(np != NULL);
      }
    }

    HASH_ITER(phh, processes, process, tmp) {
      // now migrate up to newly freed DRAM space
      for (migrated_bytes = 0; migrated_bytes < process->migrate_up_bytes;) {
        if (migrated_bytes >= PEBS_MIGRATE_UP_RATE) {
          break;
        }
        p = dequeue_page(&(process->nvm_hot_list));
        if (p == NULL) {
          // no hot pages to move up
          break;
        }
        nvm_hot_pages--;

        if (p == process->cur_cool_in_nvm) {
          process->cur_cool_in_nvm = process->nvm_hot_list.last;
        }

        // compute the access samples this page would have had if it were up to date
        // with cooling
        for (int j = 0; j < NPBUFTYPES; j++) {
          tmp_accesses[j] = p->accesses[j] >> (global_clock - p->local_clock);
        }

        if ((tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD]) < HOT_READ_THRESHOLD) {
          // page has been cooled and is no longer hot, just move to cold list
          p->hot = false;
          enqueue_page(&(process->nvm_cold_list), p);
          nvm_cold_pages++;
          continue;
        }

        np = dequeue_page(&dram_free_list);
        if (np == NULL) {
          // no free dram pages, put back in nvm hot list for now
          enqueue_page(&(process->nvm_hot_list), p);
          nvm_hot_pages++;
          break;
        }
        assert(!np->present);

        old_offset = p->devdax_offset;
        pebs_migrate_up(process, p, np->devdax_offset);
        np->devdax_offset = old_offset;
        np->in_dram = false;
        np->present = false;
        np->hot = false;
        for (int i = 0; i < NPBUFTYPES; i++) {
          np->accesses[i] = 0;
          np->tot_accesses[i] = 0;
        }

        enqueue_page(&(process->dram_hot_list), p);
        dram_hot_pages++;
        enqueue_page(&nvm_free_list, np);
        migrated_bytes += pt_to_pagesize(p->pt);
      }

      // cool process's pages
      process->cur_cool_in_dram = partial_cool(process, true);
      process->cur_cool_in_nvm = partial_cool(process, false);

      // reset migrate up and down bytes for next policy thread iteration
      process->migrate_up_bytes = process->migrate_down_bytes = 0;
    }

    LOG_TIME("migrate: %f s\n", elapsed(&start, &end));
  }


  return NULL;
}

#if 0
void *handle_miss_ratio()
{
    struct hemem_process *process, *tmp;
    double real_miss_ratio;
    for(;;) {

        HASH_ITER(phh, processes, process, tmp) {
            real_miss_ratio = 1 - 1.0 * process->accessed_pages[DRAMREAD] / (process->accessed_pages[DRAMREAD] + process->accessed_pages[NVMREAD]);
            process->accessed_pages[DRAMREAD] = 0;
            process->accessed_pages[NVMREAD] = 0;

            if (real_miss_ratio > process->expect_miss_ratio) {
                ring_buf_put(over_miss_ratio_ring, (uint64_t*)process);
            }
            else if (real_miss_ratio < process->expect_miss_ratio) {
                ring_buf_put(under_miss_ratio_ring, (uint64_t*)process);
            }
        }
    }
}
#endif

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
    enqueue_page(&(process->dram_cold_list), page);
    dram_cold_pages++;

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
    enqueue_page(&(process->nvm_cold_list), page);
    nvm_cold_pages++;

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
  if (process->priority == LATENCYCRITICAL) {
    enqueue_process(&lc_list, process);
  } else {
    enqueue_process(&be_list, process);
  }
}

void pebs_init(void)
{
  pthread_t kswapd_thread;
  pthread_t scan_thread;
  int ret;

  LOG("pebs_init: started\n");

  for (int i = 0; i < PEBS_NPROCS; i++) {
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
    pthread_mutex_init(&(p->page_lock), NULL);

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
    pthread_mutex_init(&(p->page_lock), NULL);

    enqueue_page(&nvm_free_list, p);
  }

  ret = pthread_create(&scan_thread, NULL, pebs_scan_thread, NULL);
  assert(ret == 0);
  
  ret = pthread_create(&kswapd_thread, NULL, pebs_policy_thread, NULL);
  assert(ret == 0);
  
#if 0  
  ret = pthread_create(&miss_ratio_thread, NULL, handle_miss_ratio, 0);
  if (ret != 0) {
    perror("pthread_create");
    assert(0);
  }

  uint64_t **buffer;
  buffer = (uint64_t**)malloc(sizeof(uint64_t*) * MAX_PROCESSES);
  assert(buffer);
  over_miss_ratio_ring = ring_buf_init(buffer, MAX_PROCESSES);

  buffer = (uint64_t**)malloc(sizeof(uint64_t*) * MAX_PROCESSES);
  assert(buffer);
  under_miss_ratio_ring = ring_buf_init(buffer, MAX_PROCESSES);
#endif
    
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

  LOG_STATS("\tnum_processes: [%u]\tlc_processes: [%ld]\tdram_hot: [%lu]\tdram_cold: [%lu]\tnvm_hot: [%lu]\tnvm_cold: [%lu]\tdram_free: [%lu]\tnvm_free: [%lu]\n",
        HASH_CNT(phh, processes),
        lc_list.numentries,
        dram_hot_pages,
        dram_cold_pages,
        nvm_hot_pages,
        nvm_cold_pages,
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
  hemem_pages_cnt = total_pages_cnt = other_processes_cnt = throttle_cnt = unthrottle_cnt = 0;
  
}

