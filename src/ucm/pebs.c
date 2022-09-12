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

static struct fifo_list dram_free_list;
static struct fifo_list nvm_free_list;
static ring_handle_t free_page_ring;
static pthread_mutex_t free_page_ring_lock = PTHREAD_MUTEX_INITIALIZER;
uint64_t global_clock = 0;

uint64_t hemem_pages_cnt = 0;
uint64_t other_pages_cnt = 0;
uint64_t other_processes_cnt = 0;
uint64_t total_pages_cnt = 0;
uint64_t zero_pages_cnt = 0;
uint64_t throttle_cnt = 0;
uint64_t unthrottle_cnt = 0;
uint64_t cools = 0;

static struct perf_event_mmap_page *perf_page[PEBS_NPROCS][NPBUFTYPES];
int pfd[PEBS_NPROCS][NPBUFTYPES];

volatile bool need_cool_dram = false;
volatile bool need_cool_nvm = false;

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

              //printf("page pid=%d, tid=%d\n", ps->pid, ps->tid);
              if (process != NULL) {
                //printf("ps adr:0x%llx, type: %d\n", ps->addr, j);
                //printf("page pid=%d, tid=%d, ps addr:0x%llx\n", ps->pid, ps->tid, ps->addr);
                page = find_page(process, pfn);
                if (page != NULL) {
                  //printf("page pid=%d, tid=%d, ps addr:0x%llx\n", ps->pid, ps->tid, ps->addr);
                  //printf("find page, ps adr:0x%llx, type: %d\n", ps->addr, j);
                  if (page->va != 0) {
                    page->accesses[j]++;
                    page->tot_accesses[j]++;
                    //if (page->accesses[WRITE] >= HOT_WRITE_THRESHOLD) {
                    //  if (!page->hot && !page->ring_present) {
                    //    make_hot_request(process, page);
                    //  }
                    //}
                    /* else */if (page->accesses[DRAMREAD] + page->accesses[NVMREAD] >= HOT_READ_THRESHOLD) {
                      if (!page->hot && !page->ring_present) {
                        make_hot_request(process, page);
                      }
                    }
                    else if (/*page->accesses[WRITE] < HOT_WRITE_THRESHOLD) &&*/ (page->accesses[DRAMREAD] + page->accesses[NVMREAD] < HOT_READ_THRESHOLD)) {
                      if (page->hot && !page->ring_present) {
                        make_cold_request(process, page);
                      }
                  }

                    page->accesses[DRAMREAD] >>= (global_clock - page->local_clock);
                    page->accesses[NVMREAD] >>= (global_clock - page->local_clock);
                    //page->accesses[WRITE] >>= (global_clock - page->local_clock);
                    page->local_clock = global_clock;
                    if (page->accesses[j] > PEBS_COOLING_THRESHOLD) {
                      global_clock++;
                      cools++;
                      process->need_cool_dram = true;
                      process->need_cool_nvm = true;
                    }
                  }
                  hemem_pages_cnt++;
                }
                else {
                  fprintf(stderr, "did not find page %llx\n", pfn);
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
          //fprintf(stderr, "%s event!\n",
          //   ph->type == PERF_RECORD_THROTTLE ? "THROTTLE" : "UNTHROTTLE");
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
  printf("pebs_migrate_up, addr:0x%lx\n", page->va);
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
    page_list_remove_page(&(process->dram_cold_list), page);
    page->hot = true;
    enqueue_fifo(&(process->dram_hot_list), page);
  }
  else {
    assert(page->list == &(process->nvm_cold_list));
    page_list_remove_page(&(process->nvm_cold_list), page);
    page->hot = true;
    enqueue_fifo(&(process->nvm_hot_list), page);
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
    page_list_remove_page(&(process->dram_hot_list), page);
    page->hot = false;
    enqueue_fifo(&(process->dram_cold_list), page);
  }
  else {
    assert(page->list == &(process->nvm_hot_list));
    page_list_remove_page(&(process->nvm_hot_list), page);
    page->hot = false;
    enqueue_fifo(&(process->nvm_cold_list), page);
  }
}

struct hemem_page* partial_cool_peek_and_move(struct hemem_process* process, bool dram, struct hemem_page* current)
{
  struct hemem_page *p;
  uint64_t tmp_accesses[NPBUFTYPES];
  struct fifo_list* hot;
  struct fifo_list* cold;

  if (dram) {
    hot = &(process->dram_hot_list);
    cold = &(process->dram_cold_list);
  }
  else {
    hot = &(process->nvm_hot_list);
    cold = &(process->nvm_cold_list);
  }

  if (dram && !process->need_cool_dram) {
    return current;
  }
  if (!dram && !process->need_cool_nvm) {
    return current;
  }

  if (process->start_dram_page == NULL && dram) {
      process->start_dram_page = hot->last;
  }

  if (process->start_nvm_page == NULL && !dram) {
      process->start_nvm_page = hot->last;
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
    
    if (dram && (p == process->start_dram_page)) {
        process->start_dram_page = NULL;
        process->need_cool_dram = false;
    }

    if (!dram && (p == process->start_nvm_page)) {
        process->start_nvm_page = NULL;
        process->need_cool_nvm = false;
    } 

    if (!p->hot) {
        current = p->next;
        page_list_remove_page(hot, p);
        enqueue_fifo(cold, p);
    }
    else {
        current = p;
    }
  }

  return current;
}

void update_current_cool_page(struct hemem_process* process, struct hemem_page* page)
{
    if (page == NULL) {
        return;
    }

    if (page == process->cur_cool_in_dram) {
        assert(page->list == &(process->dram_hot_list));
        next_page(page->list, page, &(process->cur_cool_in_dram));
    }
    if (page == process->cur_cool_in_nvm) {
        assert(page->list == &(process->nvm_hot_list));
        next_page(page->list, page, &(process->cur_cool_in_nvm));
    }
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
  int num_ring_reqs;
  struct hemem_page* page = NULL;
  int ret;

  thread = pthread_self();
  CPU_ZERO(&cpuset);
  CPU_SET(MIGRATION_THREAD_CPU, &cpuset);
  ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (ret != 0) {
    perror("pthread_setaffinity_np");
    assert(0);
  }

  for (;;) {
    struct hemem_process *process, *tmp;

    HASH_ITER(hh, processes, process, tmp) {
      // free pages using free page ring buffer
      while(!ring_buf_empty(process->free_page_ring)) {
        struct fifo_list *list;
        page = (struct hemem_page*)ring_buf_get(process->free_page_ring);
        if (page == NULL) {
          continue;
        }
        
        list = page->list;
        assert(list != NULL);
        update_current_cool_page(process, page);
        page_list_remove_page(list, page);
        if (page->in_dram) {
            enqueue_fifo(&dram_free_list, page);
        }
        else {
            enqueue_fifo(&nvm_free_list, page);
        }
      }

      num_ring_reqs = 0;
      // handle hot requests from hot buffer by moving pages to hot list
      while(!ring_buf_empty(process->hot_ring) && num_ring_reqs < HOT_RING_REQS_THRESHOLD) {
		page = (struct hemem_page*)ring_buf_get(process->hot_ring);
        if (page == NULL) {
            continue;
        }
       
        update_current_cool_page(process, page);
        page->ring_present = false;
        num_ring_reqs++;
        make_hot(process, page);
        //printf("hot ring, hot pages:%llu\n", num_ring_reqs);
	 }

      num_ring_reqs = 0;
      // handle cold requests from cold buffer by moving pages to cold list
      while(!ring_buf_empty(process->cold_ring) && num_ring_reqs < COLD_RING_REQS_THRESHOLD) {
        page = (struct hemem_page*)ring_buf_get(process->cold_ring);
        if (page == NULL) {
            continue;
        }

        update_current_cool_page(process, page);
        page->ring_present = false;
        num_ring_reqs++;
        make_cold(process, page);
        //printf("cold ring, cold pages:%llu\n", num_ring_reqs);
      }
    
      // move each hot NVM page to DRAM
      for (migrated_bytes = 0; migrated_bytes < PEBS_KSWAPD_MIGRATE_RATE;) {
        p = dequeue_fifo(&(process->nvm_hot_list));
        if (p == NULL) {
          // nothing in NVM is currently hot -- bail out
          break;
        }

        update_current_cool_page(process, page);
      
        if (/*(p->accesses[WRITE] < HOT_WRITE_THRESHOLD) &&*/ (p->accesses[DRAMREAD] + p->accesses[NVMREAD] < HOT_READ_THRESHOLD)) {
          // it has been cooled, need to move it into the cold list
          p->hot = false;
          enqueue_fifo(&(process->nvm_cold_list), p); 
          continue;
        } 

        for (tries = 0; tries < 2; tries++) {
          // find a free DRAM page
          np = dequeue_fifo(&dram_free_list);

          if (np != NULL) {
            assert(!(np->present));

            update_current_cool_page(process, np);

            //TODO: fix the stats
            //LOG("%lx: cold %lu -> hot %lu\t slowmem.hot: %lu, slowmem.cold: %lu\t fastmem.hot: %lu, fastmem.cold: %lu\n",
//                p->va, p->devdax_offset, np->devdax_offset, process->nvm_hot_list.numentries, process->nvm_cold_list.numentries, process->dram_hot_list.numentries, process->dram_cold_list.numentries);

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

            enqueue_fifo(&(process->dram_hot_list), p);
            enqueue_fifo(&nvm_free_list, np);

            migrated_bytes += pt_to_pagesize(p->pt);
            break;
          }

          // no free dram page, try to find a cold dram page to move down
          cp = dequeue_fifo(&(process->dram_cold_list));
          if (cp == NULL) {
            // all dram pages are hot, so put it back in list we got it from
            enqueue_fifo(&(process->nvm_hot_list), p);
            goto out;
          }
          assert(cp != NULL);

          update_current_cool_page(process, cp);
         
          // find a free nvm page to move the cold dram page to
          np = dequeue_fifo(&nvm_free_list);
          if (np != NULL) {
            assert(!(np->present));

            update_current_cool_page(process, np);

            //todo: fix the stats
            //LOG("%lx: hot %lu -> cold %lu\t slowmem.hot: %lu, slowmem.cold: %lu\t fastmem.hot: %lu, fastmem.cold: %lu\n",
                //cp->va, cp->devdax_offset, np->devdax_offset, process->nvm_hot_list.numentries, process->nvm_cold_list.numentries, process->dram_hot_list.numentries, process->dram_cold_list.numentries);

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

            enqueue_fifo(&(process->nvm_cold_list), cp);
            enqueue_fifo(&dram_free_list, np);
          }
          assert(np != NULL);
        }
      }

      process->cur_cool_in_dram = partial_cool_peek_and_move(process, true, process->cur_cool_in_dram);
      process->cur_cool_in_nvm = partial_cool_peek_and_move(process, false, process->cur_cool_in_nvm);
    }
 
out:
    LOG_TIME("migrate: %f s\n", elapsed(&start, &end));
  }

  return NULL;
}

static struct hemem_page* pebs_allocate_page(struct hemem_process* process)
{
  struct timeval start, end;
  struct hemem_page *page;

  gettimeofday(&start, NULL);
  page = dequeue_fifo(&dram_free_list);
  if (page != NULL) {
    assert(page->in_dram);
    assert(!page->present);

    page->present = true;
    enqueue_fifo(&(process->dram_cold_list), page);

    gettimeofday(&end, NULL);
    LOG_TIME("mem_policy_allocate_page: %f s\n", elapsed(&start, &end));

    return page;
  }
    
  // DRAM is full, fall back to NVM
  page = dequeue_fifo(&nvm_free_list);
  if (page != NULL) {
    assert(!page->in_dram);
    assert(!page->present);

    page->present = true;
    enqueue_fifo(&(process->nvm_cold_list), page);


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

  LOG("pebs: remove page, put this page into free_page_ring: va: 0x%lx\n", page->va);

  pthread_mutex_lock(&free_page_ring_lock);
  while (ring_buf_full(free_page_ring));
  ring_buf_put(free_page_ring, (uint64_t*)page); 
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

    enqueue_fifo(&dram_free_list, p);
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

    enqueue_fifo(&nvm_free_list, p);
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

  LOG_STATS("\themem_pages:[%lu]total_pages: [%lu]\tzero_pages: [%ld]\tother_processes: [%ld]\tthrottle/unthrottle: [%ld/%ld]\tcools: [%ld]\n",
        hemem_pages_cnt,
        total_pages_cnt,
        zero_pages_cnt,
        other_processes_cnt,
        throttle_cnt,
        unthrottle_cnt,
        cools);
  hemem_pages_cnt = total_pages_cnt = other_processes_cnt = throttle_cnt = unthrottle_cnt = 0;
  
}
