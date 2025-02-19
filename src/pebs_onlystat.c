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

#define NUM_CHA_BOXES 18

double smoothed_occ_local, occ_local;
double smoothed_occ_remote, occ_remote;
double smoothed_inserts_local, inserts_local;
double smoothed_inserts_remote, inserts_remote;

uint64_t hemem_cpu_start;
uint64_t migration_thread_cpu;
uint64_t scanning_thread_cpu;

#ifdef DUMP_FREQ
volatile bool end_pebs_sampling = false;
#endif

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

static ring_handle_t free_page_ring;
static pthread_mutex_t free_page_ring_lock = PTHREAD_MUTEX_INITIALIZER;
uint64_t global_clock;

uint64_t hemem_pages_cnt = 0;
uint64_t other_pages_cnt = 0;
uint64_t total_pages_cnt = 0;
uint64_t accesses_cnt[NPBUFTYPES];
uint64_t core_accesses_cnt[PEBS_NPROCS];
uint64_t zero_pages_cnt = 0;
uint64_t throttle_cnt = 0;
uint64_t unthrottle_cnt = 0;
uint64_t cools = 0;

_Atomic volatile double miss_ratio = -1.0;
FILE *miss_ratio_f = NULL;

static struct perf_event_mmap_page *perf_page[PEBS_NPROCS][NPBUFTYPES];
int pfd[PEBS_NPROCS][NPBUFTYPES];
int pebs_core_list[] = {1,3,5,7,9,11,13,15}; // should contain PEBS_NPROCS entries

volatile bool need_cool_dram;
volatile bool need_cool_nvm;

struct hemem_page* start_dram_page;
struct hemem_page* start_nvm_page;

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

  pfd[cpu][type] = perf_event_open(&attr, -1, pebs_core_list[cpu], -1, 0);
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

void *pebs_scan_thread()
{
#ifdef SAMPLE_BASED_COOLING
  uint64_t samples_since_cool = 0;
#endif

  cpu_set_t cpuset;
  pthread_t thread;

  thread = pthread_self();
  CPU_ZERO(&cpuset);
  CPU_SET(scanning_thread_cpu, &cpuset);
  int s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (s != 0) {
    perror("pthread_setaffinity_np");
    assert(0);
  }

  uint32_t my_pid = getpid();

  for(;;) {
    #ifdef DUMP_FREQ
    if(end_pebs_sampling) {
      return NULL;
    }
    #endif
    for (int i = start_cpu; i < start_cpu + num_cores; i++) {
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

        switch(ph->type) {
        case PERF_RECORD_SAMPLE:
            ps = (struct perf_sample*)ph;
            assert(ps != NULL);
            if(ps->addr != 0 && ps->pid == my_pid) {
              __u64 pfn = ps->addr & HUGE_PFN_MASK;
            
              page = get_hemem_page(pfn);
              if (page != NULL) {
                if (page->va != 0) {
                  assert(ps->pid == my_pid);
                  page->accesses[j]++;
                  page->tot_accesses[j]++;
                  #ifdef HISTOGRAM
                  if(!page->ring_present){
                    histogram_update_request(page);
                  }
                  #else 
                  //if (page->accesses[WRITE] >= HOT_WRITE_THRESHOLD) {
                  //  if (!page->hot && !page->ring_present) {
                  //      make_hot_request(page);
                  //  }
                  //}
                  /*else*/ if (page->accesses[DRAMREAD] + page->accesses[NVMREAD] >= HOT_READ_THRESHOLD) {
                    if (!page->hot && !page->ring_present) {
                        make_hot_request(page);
                    }
                  }
                  else if (/*(page->accesses[WRITE] < HOT_WRITE_THRESHOLD) &&*/ (page->accesses[DRAMREAD] + page->accesses[NVMREAD] < HOT_READ_THRESHOLD)) {
                    if (page->hot && !page->ring_present) {
                        make_cold_request(page);
                    }
                 }
                 #endif

                  accesses_cnt[j]++;
                  core_accesses_cnt[i]++;

                  page->accesses[DRAMREAD] >>= (global_clock - page->local_clock);
                  page->accesses[NVMREAD] >>= (global_clock - page->local_clock);
                  //page->accesses[WRITE] >>= (global_clock - page->local_clock);
                  page->local_clock = global_clock;
                  #ifndef SAMPLE_BASED_COOLING
                  if (page->accesses[j] > PEBS_COOLING_THRESHOLD) {
                    global_clock++;
                    cools++;
                    need_cool_dram = true;
                    need_cool_nvm = true;
                  }
                  #else
                  if (samples_since_cool > SAMPLE_COOLING_THRESHOLD) {
                    global_clock++;
                    cools++;
                    need_cool_dram = true;
                    need_cool_nvm = true;
                    samples_since_cool = 0;
                  }
                  #endif
                }
                #ifdef SAMPLE_BASED_COOLING
                samples_since_cool++;
                #endif
                hemem_pages_cnt++;
              }
              else {
                other_pages_cnt++;
              }
            
              total_pages_cnt++;
            }
            else {
              if(ps->addr == 0) {
                zero_pages_cnt++;
              } else {
                other_pages_cnt++;
                total_pages_cnt++;
              }
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

void *pebs_policy_thread()
{
  cpu_set_t cpuset;
  pthread_t thread;
  struct timeval start, end, begin;
  // int tries;
  struct hemem_page *p;
  // struct hemem_page *cp;
  struct hemem_page *np;
  uint64_t migrated_bytes, migrate_limit;
  uint64_t old_offset;
  int num_ring_reqs;
  struct hemem_page* page = NULL;
  double migrate_time;
  // double delta_occ;
  #ifdef COOL_IN_PLACE
  struct hemem_page* cur_cool_in_dram  = NULL;
  struct hemem_page* cur_cool_in_nvm = NULL;
  #endif
  double beta;
  #if defined HISTOGRAM || defined SCAN_AND_SORT
  uint64_t total_accesses = 0;
  double pi, pj, target_delta, best_delta;
  int best_i, best_j;
  #endif
  #ifdef SCAN_AND_SORT
  struct page_freq* dram_page_freqs = NULL;
  int dram_freqs_count = 0;
  struct page_freq* nvm_page_freqs = NULL;
  int nvm_freqs_count = 0;
  int cur_j;
  struct page_freq* top;
  int top_count;
  struct page_freq* bottom;
  int bottom_count;
  int dram_i, nvm_j;
  // struct hemem_page *tmp_dram_page = NULL;
  // struct hemem_page *tmp_nvm_page = NULL;
  // uint64_t dlimit;
  // double cur_p;
  #endif
  
  thread = pthread_self();
  CPU_ZERO(&cpuset);
  CPU_SET(migration_thread_cpu, &cpuset);
  int s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (s != 0) {
    perror("pthread_setaffinity_np");
    assert(0);
  }

  colloid_setup(migration_thread_cpu);

  #ifdef SCAN_AND_SORT
  dram_page_freqs = calloc(dramsize/PAGE_SIZE, sizeof(struct page_freq));
  if(dram_page_freqs == NULL) {
    perror("failed to allocate dram_page_freqs");
    assert(0);
  }
  nvm_page_freqs = calloc(nvmsize/PAGE_SIZE, sizeof(struct page_freq));
  if(nvm_page_freqs == NULL) {
    perror("failed to allocate nvm_page_freqs");
    assert(0);
  }
  #endif
  
  gettimeofday(&begin, NULL);

  for (;;) {
    #ifdef DUMP_FREQ
    if(end_pebs_sampling) {
      return NULL;
    }
    #endif
    gettimeofday(&start, NULL);
    
    // Cool the histograms
    // #ifdef HISTOGRAM
    // histogram_shift(&dram_histogram_list[0], global_clock - histogram_clock);
    // histogram_shift(&nvm_histogram_list[0], global_clock - histogram_clock);
    // histogram_clock = global_clock;
    // #endif

    colloid_update_stats();
    
    // if(elapsed(&begin, &start) > 200.0) {
    //   // stop migrations
    //   // colloid_printf("occ_local: %lf, occ_remote: %lf\n", smoothed_occ_local, smoothed_occ_remote);
    //   colloid_printf("occ_local: %lf, occ_remote: %lf, best_i: %d, best_j: %d, migrated_bytes=%lu, total_accesses=%lu, freq_i=%lu, freq_j=%lu, top_freq_i=%lu, top_freq_j=%lu, inserts_local=%lf, inserts_remote=%lf, inst_occ_local=%lf, inst_occ_remote=%lf, inst_inserts_local=%lf, inst_inserts_remote=%lf\n", smoothed_occ_local, smoothed_occ_remote, 0, 0, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL, smoothed_inserts_local, smoothed_inserts_remote, occ_local, occ_remote, inserts_local, inserts_remote);
    //   goto out;
    // }

    beta = colloid_beta();

    // Pair finding algorithm
    #ifdef HISTOGRAM
    // TODO: Compare based on some precision threshold
    if(smoothed_occ_local == beta * smoothed_occ_remote) {
      // nothing to do
      colloid_printf("equal occupancy exit\n");
      goto out;
    }
    target_delta = fabs(smoothed_occ_local - beta * smoothed_occ_remote);
    target_delta /= (smoothed_occ_local+smoothed_occ_remote);
    total_accesses = 0;

    #elif defined SCAN_AND_SORT
    // TODO: Compare based on some precision threshold
    if(smoothed_occ_local == beta * smoothed_occ_remote) {
      // nothing to do
      colloid_printf("equal occupancy exit\n");
      colloid_printf("equal occupancy exit\n");
      goto out;
    }

    total_accesses = 0;
    // Scan page lists and build frequency arrays
    dram_freqs_count = 0;
    nvm_freqs_count = 0;
    dram_freqs_count += scan_page_list(&dram_hot_list, dram_page_freqs+dram_freqs_count, dramsize/PAGE_SIZE-dram_freqs_count, &total_accesses);
    dram_freqs_count += scan_page_list(&dram_cold_list, dram_page_freqs+dram_freqs_count, dramsize/PAGE_SIZE-dram_freqs_count, &total_accesses);
    nvm_freqs_count += scan_page_list(&nvm_hot_list, nvm_page_freqs+nvm_freqs_count, nvmsize/PAGE_SIZE-nvm_freqs_count, &total_accesses);
    nvm_freqs_count += scan_page_list(&nvm_cold_list, nvm_page_freqs+nvm_freqs_count, nvmsize/PAGE_SIZE-nvm_freqs_count, &total_accesses);

    if(total_accesses == 0) {
      colloid_printf("total_accesses=0 exit\n");
      goto out;
    }

    // Sort frequency arrays in increasing order
    qsort(dram_page_freqs, dram_freqs_count, sizeof(struct page_freq), cmp_page_freq);
    qsort(nvm_page_freqs, nvm_freqs_count, sizeof(struct page_freq), cmp_page_freq);
  
    target_delta = colloid_target_delta(beta);

    // Try to add temp pages with 0 access frequency
    // tmp_dram_page = dequeue_fifo(&dram_free_list);
    // if(tmp_dram_page != NULL) {
    //   dram_page_freqs[dram_freqs_count].accesses = 0;
    //   dram_page_freqs[dram_freqs_count].page = tmp_dram_page;
    //   dram_freqs_count++;
    // }
    // tmp_nvm_page = dequeue_fifo(&nvm_free_list);
    // if(tmp_nvm_page != NULL) {
    //   nvm_page_freqs[nvm_freqs_count].accesses = 0;
    //   nvm_page_freqs[nvm_freqs_count].page = tmp_nvm_page;
    //   nvm_freqs_count++;
    // }

    migrate_limit = (50 * PAGE_SIZE);
    #ifdef COLLOID_DYNAMIC_LIMITbe
    dlimit = (uint64_t)(target_delta * (smoothed_inserts_local + smoothed_inserts_remote) * NUM_CHA_BOXES * 64);
    if(migrate_limit > dlimit) {
      migrate_limit = dlimit;
    }  
    #endif

    colloid_log_pre();
    colloid_printf( 
    ",target_delta=%lf"
    ",total_accesses=%lu"
    ",top_freq_i=%lu"
    ",top_freq_j=%lu"
    ",migrate_limit=%lu\n",
    target_delta,
    total_accesses,
    dram_page_freqs[dram_freqs_count-1].accesses,
    nvm_page_freqs[nvm_freqs_count-1].accesses,
    migrate_limit);

    #endif

out:
    gettimeofday(&end, NULL);
    // elapsed time in us
    migrate_time = elapsed(&start, &end) * 1000000.0;
    if (migrate_time < (1.0 * PEBS_KSWAPD_INTERVAL)) {
      usleep((uint64_t)((1.0 * PEBS_KSWAPD_INTERVAL) - migrate_time));
    }
 
    LOG_TIME("migrate: %f s\n", elapsed(&start, &end));
  }

  return NULL;
}

static struct hemem_page* pebs_allocate_page()
{
  struct timeval start, end;
  struct hemem_page *page;

  gettimeofday(&start, NULL);
  page = dequeue_fifo(&dram_free_list);
  if (page != NULL) {
    assert(page->in_dram);
    assert(!page->present);

    page->present = true;
    #ifdef HISTOGRAM
    // TODO: what happens if histogram cooling happens concurrently?
    enqueue_fifo(&dram_histogram_list[0], page);
    // page->local_histogram_clock = histogram_clock;
    #else
    enqueue_fifo(&dram_cold_list, page);
    #endif

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
    #ifdef HISTOGRAM
    // TODO: what happens if histogram cooling happens concurrently?
    enqueue_fifo(&nvm_histogram_list[0], page);
    // page->local_histogram_clock = histogram_clock;
    #else
    enqueue_fifo(&nvm_cold_list, page);
    #endif


    gettimeofday(&end, NULL);
    LOG_TIME("mem_policy_allocate_page: %f s\n", elapsed(&start, &end));

    return page;
  }

  assert(!"Out of memory");
}

struct hemem_page* pebs_pagefault(void)
{
  struct hemem_page *page;

  // do the heavy lifting of finding the devdax file offset to place the page
  page = pebs_allocate_page();
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

  // Take page lock to prevent pages that are currently being migrated from being unmapped
  pthread_mutex_lock(&(page->page_lock));
  page->present = false;
  pthread_mutex_unlock(&(page->page_lock));
  page->hot = false;
  for (int i = 0; i < NPBUFTYPES; i++) {
    page->accesses[i] = 0;
    page->tot_accesses[i] = 0;
  }
}

#ifdef DUMP_FREQ
void pebs_sigint_handler(int dummy) {

  struct hemem_page *p;
  FILE *dump_freq_f = NULL; 

  // Stop pebs monitoring thread and migration thread
  end_pebs_sampling = true;
  sleep(5);

  // Scan pages and log access frequency to file
  dump_freq_f = fopen("/tmp/hemem-dump-freq.log", "w");
  if(dump_freq_f == NULL) {
    fprintf(stderr, "open freq dump log file failed\n");
    exit(-1);
  }

  #ifdef HISTOGRAM
  for(int i = 0; i < MAX_HISTOGRAM_BINS; i++) {
    while((p = dequeue_fifo(&dram_histogram_list[i])) != NULL) {
      fprintf(dump_freq_f, "%lu %lu\n", p->tot_accesses[DRAMREAD] + p->tot_accesses[NVMREAD], (p->accesses[DRAMREAD] >> (global_clock - p->local_clock)) + (p->accesses[NVMREAD] >> (global_clock - p->local_clock)));
    }
    while((p = dequeue_fifo(&nvm_histogram_list[i])) != NULL) {
      fprintf(dump_freq_f, "%lu %lu\n", p->tot_accesses[DRAMREAD] + p->tot_accesses[NVMREAD], (p->accesses[DRAMREAD] >> (global_clock - p->local_clock)) + (p->accesses[NVMREAD] >> (global_clock - p->local_clock)));
    }
  }
  #else
  while((p = dequeue_fifo(&dram_hot_list)) != NULL) {
    fprintf(dump_freq_f, "%lu %lu\n", p->tot_accesses[DRAMREAD] + p->tot_accesses[NVMREAD], (p->accesses[DRAMREAD] >> (global_clock - p->local_clock)) + (p->accesses[NVMREAD] >> (global_clock - p->local_clock)));
  }
  while((p = dequeue_fifo(&dram_cold_list)) != NULL) {
    fprintf(dump_freq_f, "%lu %lu\n", p->tot_accesses[DRAMREAD] + p->tot_accesses[NVMREAD], (p->accesses[DRAMREAD] >> (global_clock - p->local_clock)) + (p->accesses[NVMREAD] >> (global_clock - p->local_clock)));
  }
  while((p = dequeue_fifo(&nvm_hot_list)) != NULL) {
    fprintf(dump_freq_f, "%lu %lu\n", p->tot_accesses[DRAMREAD] + p->tot_accesses[NVMREAD], (p->accesses[DRAMREAD] >> (global_clock - p->local_clock)) + (p->accesses[NVMREAD] >> (global_clock - p->local_clock)));
  }
  while((p = dequeue_fifo(&nvm_cold_list)) != NULL) {
    fprintf(dump_freq_f, "%lu %lu\n", p->tot_accesses[DRAMREAD] + p->tot_accesses[NVMREAD], (p->accesses[DRAMREAD] >> (global_clock - p->local_clock)) + (p->accesses[NVMREAD] >> (global_clock - p->local_clock)));
  }
  #endif

  fclose(dump_freq_f);
  printf("dumped freq log\n");
  fflush(stdout);

  exit(-1);
}
#endif

void pebs_init(void)
{
  pthread_t kswapd_thread;
  pthread_t scan_thread;
  uint64_t** buffer;
  char logpath[32];
  
  #ifdef DUMP_FREQ
  signal(SIGINT, pebs_sigint_handler);
  #endif

  LOG("pebs_init: started\n");

  snprintf(&logpath[0], sizeof(logpath) - 1, "/tmp/log-%d.txt", getpid());
  miss_ratio_f = fopen(logpath, "w");
  if (miss_ratio_f == NULL) {
    perror("miss ratio file fopen");
  }
  assert(miss_ratio_f != NULL);

  char* start_cpu_string = getenv("HEMEM_MGR_START_CPU");
  if(start_cpu_string != NULL)
    hemem_cpu_start = strtoull(start_cpu_string, NULL, 10);
  else
    hemem_cpu_start = START_THREAD_DEFAULT;
  
  scanning_thread_cpu = 4;
  migration_thread_cpu = 2;

  for (int i = start_cpu; i < start_cpu + num_cores; i++) {
    //perf_page[i][READ] = perf_setup(0x1cd, 0x4, i);  // MEM_TRANS_RETIRED.LOAD_LATENCY_GT_4
    //perf_page[i][READ] = perf_setup(0x81d0, 0, i);   // MEM_INST_RETIRED.ALL_LOADS
    perf_page[i][DRAMREAD] = perf_setup(0x1d3, 0, i, DRAMREAD);      // MEM_LOAD_L3_MISS_RETIRED.LOCAL_DRAM
    // perf_page[i][NVMREAD] = perf_setup(0x80d1, 0, i, NVMREAD);     // MEM_LOAD_RETIRED.LOCAL_PMM
    perf_page[i][NVMREAD] = perf_setup(0x2d3, 0, i, NVMREAD);         // MEM_LOAD_L3_MISS_RETIRED.REMOTE_DRAM
    //perf_page[i][WRITE] = perf_setup(0x82d0, 0, i, WRITE);    // MEM_INST_RETIRED.ALL_STORES
    //perf_page[i][WRITE] = perf_setup(0x12d0, 0, i);   // MEM_INST_RETIRED.STLB_MISS_STORES
  }

  pthread_mutex_init(&(dram_free_list.list_lock), NULL);
  for (int i = 0; i < dramsize / PAGE_SIZE; i++) {
    struct hemem_page *p = calloc(1, sizeof(struct hemem_page));
    p->devdax_offset = i * PAGE_SIZE + dramoffset;
    p->present = false;
    p->in_dram = true;
    p->ring_present = false;
    p->pt = pagesize_to_pt(PAGE_SIZE);
    pthread_mutex_init(&(p->page_lock), NULL);

    enqueue_fifo(&dram_free_list, p);
  }

  pthread_mutex_init(&(nvm_free_list.list_lock), NULL);
  for (int i = 0; i < nvmsize / PAGE_SIZE; i++) {
    struct hemem_page *p = calloc(1, sizeof(struct hemem_page));
    p->devdax_offset = i * PAGE_SIZE + nvmoffset;
    p->present = false;
    p->in_dram = false;
    p->ring_present = false;
    p->pt = pagesize_to_pt(PAGE_SIZE);
    pthread_mutex_init(&(p->page_lock), NULL);

    enqueue_fifo(&nvm_free_list, p);
  }

  #ifdef HISTOGRAM
  for(int i = 0; i < MAX_HISTOGRAM_BINS; i++) {
    pthread_mutex_init(&(dram_histogram_list[i].list_lock), NULL);
    pthread_mutex_init(&(nvm_histogram_list[i].list_lock), NULL);
  }
  #else
  pthread_mutex_init(&(dram_hot_list.list_lock), NULL);
  pthread_mutex_init(&(dram_cold_list.list_lock), NULL);
  pthread_mutex_init(&(nvm_hot_list.list_lock), NULL);
  pthread_mutex_init(&(nvm_cold_list.list_lock), NULL);
  #endif

  #ifndef HISTOGRAM
  buffer = (uint64_t**)malloc(sizeof(uint64_t*) * CAPACITY);
  assert(buffer); 
  hot_ring = ring_buf_init(buffer, CAPACITY);
  buffer = (uint64_t**)malloc(sizeof(uint64_t*) * CAPACITY);
  assert(buffer); 
  cold_ring = ring_buf_init(buffer, CAPACITY);
  #else
  buffer = (uint64_t**)malloc(sizeof(uint64_t*) * CAPACITY);
  assert(buffer); 
  update_ring = ring_buf_init(buffer, CAPACITY);
  #endif
  buffer = (uint64_t**)malloc(sizeof(uint64_t*) * CAPACITY);
  assert(buffer); 
  free_page_ring = ring_buf_init(buffer, CAPACITY);

  int r = pthread_create(&scan_thread, NULL, pebs_scan_thread, NULL);
  assert(r == 0);
  
  r = pthread_create(&kswapd_thread, NULL, pebs_policy_thread, NULL);
  assert(r == 0);
  
  LOG("Memory management policy is PEBS\n");

  LOG("pebs_init: finished\n");

}

void pebs_shutdown()
{
  for (int i = start_cpu; i < start_cpu + num_cores; i++) {
    for (int j = 0; j < NPBUFTYPES; j++) {
      ioctl(pfd[i][j], PERF_EVENT_IOC_DISABLE, 0);
      //munmap(perf_page[i][j], sysconf(_SC_PAGESIZE) * PERF_PAGES);
    }
  }
  // printf("PEBS shutdown\n");
  // fflush(stdout);
}

static inline double calc_miss_ratio()
{
  return ((1.0 * accesses_cnt[NVMREAD]) / (1.0 * (accesses_cnt[DRAMREAD] + accesses_cnt[NVMREAD])));
}

void pebs_stats()
{
  uint64_t total_samples = 0;
  colloid_log_stat();
  LOG_STATS("\tdram_hot_list.numentries: [%ld]\tdram_cold_list.numentries: [%ld]\tnvm_hot_list.numentries: [%ld]\tnvm_cold_list.numentries: [%ld]\themem_pages: [%lu]\ttotal_pages: [%lu]\tzero_pages: [%ld]\tthrottle/unthrottle_cnt: [%ld/%ld]\tcools: [%ld]\n",
          #ifndef HISTOGRAM 
          dram_hot_list.numentries, 
          #else 
          0UL,
          #endif
          #ifndef HISTOGRAM 
          dram_cold_list.numentries,
          #else
          0UL,
          #endif
          #ifndef HISTOGRAM
          nvm_hot_list.numentries,
          #else
          0UL,
          #endif
          #ifndef HISTOGRAM
          nvm_cold_list.numentries,
          #else
          0UL,
          #endif
          hemem_pages_cnt,
          total_pages_cnt,
          zero_pages_cnt,
          throttle_cnt,
          unthrottle_cnt,
          cools);
  LOG_STATS("\tdram_accesses: [%lu]\tnvm_accesses: [%lu]\tsamples: [", accesses_cnt[DRAMREAD], accesses_cnt[NVMREAD]);
  for (int i = 0; i < PEBS_NPROCS ; i++) {
    LOG_STATS("%lu ", core_accesses_cnt[i]);
    total_samples += core_accesses_cnt[i];
    core_accesses_cnt[i] = 0;
  }
  LOG_STATS("]\ttotal_samples: [%lu]\n", total_samples);
  #ifndef HISTOGRAM
  // fprintf(stdout, "Total: %.2f GB DRAM, %.2f GB NVM\n",
    // (double)(dram_hot_list.numentries + dram_cold_list.numentries) * ((double)PAGE_SIZE) / (1024.0 * 1024.0 * 1024.0), 
    // (double)(nvm_hot_list.numentries + nvm_cold_list.numentries) * ((double)PAGE_SIZE) / (1024.0 * 1024.0 * 1024.0));
  #endif
  #ifdef HISTOGRAM
  LOG_STATS("\t%ddram_histogram: [", 0);
  for(int i = 0; i < MAX_HISTOGRAM_BINS; i++) {
    LOG_STATS("%lu ", dram_histogram_list[i].numentries);
  }
  LOG_STATS("]%d\n", 0);
  LOG_STATS("\t%dnvm_histogram: [", 0);
  for(int i = 0; i < MAX_HISTOGRAM_BINS; i++) {
    LOG_STATS("%lu ", nvm_histogram_list[i].numentries);
  }
  LOG_STATS("]%d\n", 0);
  #endif
  fflush(stdout);
  hemem_pages_cnt = total_pages_cnt =  throttle_cnt = unthrottle_cnt = 0;

  if (accesses_cnt[DRAMREAD] + accesses_cnt[NVMREAD] != 0) {
    if (miss_ratio == -1.0) {
      miss_ratio = calc_miss_ratio();
    } else {
      miss_ratio = (EWMA_FRAC * calc_miss_ratio()) + ((1 - EWMA_FRAC) * miss_ratio);
    }
  } else {
    miss_ratio = -1.0;
  }
  accesses_cnt[DRAMREAD] = accesses_cnt[NVMREAD] = 0;

  fprintf(miss_ratio_f, "%f\n", miss_ratio);
  fflush(miss_ratio_f);
}
