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

#include "hemem.h"
#include "pebs.h"
#include "timer.h"
#include "spsc-ring.h"

#define LOCAL_NUMA 1
#define CHA_MSR_PMON_BASE 0x0E00L
#define CHA_MSR_PMON_CTL_BASE 0x0E01L
#define CHA_MSR_PMON_FILTER0_BASE 0x0E05L
//#define CHA_MSR_PMON_FILTER1_BASE 0x0E06L // No FULERT1 on Icelake
#define CHA_MSR_PMON_STATUS_BASE 0x0E07L
#define CHA_MSR_PMON_CTR_BASE 0x0E08L
#define NUM_CHA_BOXES 18 // There are 32 CHA boxes in icelake server. After the first 18 boxes, the couter offsets change.
#define NUM_CHA_COUNTERS 4

int colloid_msr_fd;
double smoothed_occ_local, occ_local;
double smoothed_occ_remote, occ_remote;
double smoothed_inserts_local, inserts_local;
double smoothed_inserts_remote, inserts_remote;
double p_lo, p_hi;
uint64_t cur_ctr_tsc[NUM_CHA_BOXES][NUM_CHA_COUNTERS], prev_ctr_tsc[NUM_CHA_BOXES][NUM_CHA_COUNTERS];
uint64_t cur_ctr_val[NUM_CHA_BOXES][NUM_CHA_COUNTERS], prev_ctr_val[NUM_CHA_BOXES][NUM_CHA_COUNTERS];

uint64_t hemem_cpu_start;
uint64_t migration_thread_cpu;
uint64_t scanning_thread_cpu;

#ifdef SCAN_AND_SORT
struct page_freq {
  uint64_t accesses;
  struct hemem_page *page;
};
#endif

#ifdef DUMP_FREQ
volatile bool end_pebs_sampling = false;
#endif

#ifdef HISTOGRAM
static struct fifo_list dram_histogram_list[MAX_HISTOGRAM_BINS];
static struct fifo_list nvm_histogram_list[MAX_HISTOGRAM_BINS];
uint64_t histogram_clock = 0;
#else
static struct fifo_list dram_hot_list;
static struct fifo_list dram_cold_list;
static struct fifo_list nvm_hot_list;
static struct fifo_list nvm_cold_list;
#endif
static struct fifo_list dram_free_list;
static struct fifo_list nvm_free_list;
#ifndef HISTOGRAM
static ring_handle_t hot_ring;
static ring_handle_t cold_ring;
#else
static ring_handle_t update_ring;
#endif
static ring_handle_t free_page_ring;
static pthread_mutex_t free_page_ring_lock = PTHREAD_MUTEX_INITIALIZER;
uint64_t global_clock = 0;

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
FILE *colloid_log_f = NULL;

static struct perf_event_mmap_page *perf_page[PEBS_NPROCS][NPBUFTYPES];
int pfd[PEBS_NPROCS][NPBUFTYPES];
int pebs_core_list[] = {1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55,57,59,61,63}; // should contain PEBS_NPROCS entries

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

static inline void sample_cha_ctr(int cha, int ctr) {
    uint32_t msr_num;
    uint64_t msr_val;
    int ret;

    msr_num = CHA_MSR_PMON_CTR_BASE + (0xE * cha) + ctr;
    ret = pread(colloid_msr_fd, &msr_val, sizeof(msr_val), msr_num);
    if (ret != sizeof(msr_val)) {
        perror("ERROR: failed to read MSR");
    }
    prev_ctr_val[cha][ctr] = cur_ctr_val[cha][ctr];
    cur_ctr_val[cha][ctr] = msr_val;
    prev_ctr_tsc[cha][ctr] = cur_ctr_tsc[cha][ctr];
    cur_ctr_tsc[cha][ctr] = rdtscp();
}

static void colloid_setup(int cpu) {
  // Open msr file
  char filename[100];
  sprintf(filename, "/dev/cpu/%d/msr", cpu);
  colloid_msr_fd = open(filename, O_RDWR);
  if(colloid_msr_fd == -1) {
    perror("Failed to open msr file");
  }

  // Setup counters
  int cha, ctr, ret;
  uint32_t msr_num;
  uint64_t msr_val;
  for(cha = 0; cha < NUM_CHA_BOXES; cha++) {
	// Icelake offset multiplier is 0xE
      msr_num = CHA_MSR_PMON_FILTER0_BASE + (0xE * cha); // Filter0
      msr_val = 0x00000000; // default; no filtering
      ret = pwrite(colloid_msr_fd,&msr_val,sizeof(msr_val),msr_num);
      if (ret != 8) {
	  printf("wrmsr FILTER0 failed for cha: %d\n", cha);
          perror("wrmsr FILTER0 failed");
      }

      //msr_num = CHA_MSR_PMON_FILTER1_BASE + (0xE * cha); // Filter1
      //msr_val = (cha%2 == 0)?(0x40432):(0x40431); // Filter DRd of local/remote on even/odd CHA boxes
      //ret = pwrite(colloid_msr_fd,&msr_val,sizeof(msr_val),msr_num);
      //if (ret != 8) {
      //    perror("wrmsr FILTER1 failed");
      //}

      msr_num = CHA_MSR_PMON_CTL_BASE + (0xE * cha) + 0; // counter 0
      msr_val = (cha%2==0)?(0x00c8168600400136):(0x00c8170600400136); // TOR Occupancy, DRd, Miss, local/remote on even/odd CHA boxes
      ret = pwrite(colloid_msr_fd,&msr_val,sizeof(msr_val),msr_num);
      if (ret != 8) {
          perror("wrmsr COUNTER0 failed");
      }

      msr_num = CHA_MSR_PMON_CTL_BASE + (0xE * cha) + 1; // counter 1
      msr_val = (cha%2==0)?(0x00c8168600400135):(0x00c8170600400135); // TOR Inserts, DRd, Miss, local/remote on even/odd CHA boxes
      ret = pwrite(colloid_msr_fd,&msr_val,sizeof(msr_val),msr_num);
      if (ret != 8) {
          perror("wrmsr COUNTER1 failed");
      }

      msr_num = CHA_MSR_PMON_CTL_BASE + (0xE * cha) + 2; // counter 2
      msr_val = 0x400000; // CLOCKTICKS
      ret = pwrite(colloid_msr_fd,&msr_val,sizeof(msr_val),msr_num);
      if (ret != 8) {
          perror("wrmsr COUNTER2 failed");
      }
  }

  // Initialize stats
  for(cha = 0; cha < NUM_CHA_BOXES; cha++) {
        for(ctr = 0; ctr < NUM_CHA_COUNTERS; ctr++) {
            cur_ctr_tsc[cha][ctr] = 0;
            cur_ctr_val[cha][ctr] = 0;
            sample_cha_ctr(cha, ctr);
        }
    }

  smoothed_occ_local = 0.0;
  occ_local = 0.0;
  smoothed_occ_remote = 0.0;
  occ_remote = 0.0;
  smoothed_inserts_local = 0.0;
  inserts_local = 0.0;
  smoothed_inserts_remote = 0.0;
  inserts_remote = 0.0;
  p_lo = 0.0;
  p_hi = 1.0;
}

static void colloid_update_stats() {
  uint64_t cum_occ, delta_tsc, cum_inserts;
  double cur_occ, cur_rate;
  // Sample counters and update state
  // TODO: For starters using CHA0 for local and CHA1 for remote
  sample_cha_ctr(0, 0); // CHA0 occupancy
  sample_cha_ctr(0, 1); // CHA0 inserts
  sample_cha_ctr(1, 0);
  sample_cha_ctr(1, 1);

  cum_occ = cur_ctr_val[0][0] - prev_ctr_val[0][0];
  delta_tsc = cur_ctr_tsc[0][0] - prev_ctr_tsc[0][0];
  cur_occ = ((double)cum_occ)/((double)delta_tsc);
  occ_local = cur_occ;
  smoothed_occ_local = COLLOID_EWMA*cur_occ + (1-COLLOID_EWMA)*smoothed_occ_local;

  cum_inserts = cur_ctr_val[0][1] - prev_ctr_val[0][1];
  // delta_tsc = cur_ctr_tsc[0][1] - prev_ctr_tsc[0][1];
  // cur_rate = ((double)cum_inserts)/((double)delta_tsc);
  inserts_local = (double)cum_inserts;
  smoothed_inserts_local = COLLOID_EWMA*((double)cum_inserts) + (1-COLLOID_EWMA)*smoothed_inserts_local;

  cum_occ = cur_ctr_val[1][0] - prev_ctr_val[1][0];
  delta_tsc = cur_ctr_tsc[1][0] - prev_ctr_tsc[1][0];
  cur_occ = ((double)cum_occ)/((double)delta_tsc);
  occ_remote = cur_occ;
  smoothed_occ_remote = COLLOID_EWMA*cur_occ + (1-COLLOID_EWMA)*smoothed_occ_remote;

  cum_inserts = cur_ctr_val[1][1] - prev_ctr_val[1][1];
  // delta_tsc = cur_ctr_tsc[1][1] - prev_ctr_tsc[1][1];
  // cur_rate = ((double)cum_inserts)/((double)delta_tsc);
  inserts_remote = (double)cum_inserts;
  smoothed_inserts_remote = COLLOID_EWMA*((double)cum_inserts) + (1-COLLOID_EWMA)*smoothed_inserts_remote;
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

static void pebs_migrate_down(struct hemem_page *page, uint64_t offset)
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

static void pebs_migrate_up(struct hemem_page *page, uint64_t offset)
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

static struct hemem_page* start_dram_page = NULL;
static struct hemem_page* start_nvm_page = NULL;

#ifdef COOL_IN_PLACE
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
static void partial_cool(struct fifo_list *hot, struct fifo_list *cold, bool dram)
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

void *pebs_policy_thread()
{
  cpu_set_t cpuset;
  pthread_t thread;
  struct timeval start, end, begin;
  int tries;
  struct hemem_page *p;
  struct hemem_page *cp;
  struct hemem_page *np;
  uint64_t migrated_bytes, migrate_limit;
  uint64_t old_offset;
  int num_ring_reqs;
  struct hemem_page* page = NULL;
  double migrate_time;
  double delta_occ;
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
  uint64_t dlimit;
  double cur_p;
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
  colloid_log_f = fopen("/tmp/hemem-colloid.log", "w");
  if(colloid_log_f == NULL) {
    perror("open colloid log file failed");
  }

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
    // free pages using free page ring buffer
    while(!ring_buf_empty(free_page_ring)) {
        struct fifo_list *list;
        page = (struct hemem_page*)ring_buf_get(free_page_ring);
        if (page == NULL) {
            continue;
        }
        
        // #ifdef HISTOGRAM
        // histogram_sync_page(page);
        // #endif
        list = page->list;
        assert(list != NULL);
        #ifdef COOL_IN_PLACE
        update_current_cool_page(&cur_cool_in_dram, &cur_cool_in_nvm, page);
        #endif
        page_list_remove_page(list, page);
        if (page->in_dram) {
            enqueue_fifo(&dram_free_list, page);
        }
        else {
            enqueue_fifo(&nvm_free_list, page);
        }
    }

    // Cool the histograms
    // #ifdef HISTOGRAM
    // histogram_shift(&dram_histogram_list[0], global_clock - histogram_clock);
    // histogram_shift(&nvm_histogram_list[0], global_clock - histogram_clock);
    // histogram_clock = global_clock;
    // #endif

    #ifdef HISTOGRAM
    num_ring_reqs = 0;
    // handle requests from the update buffer
    while(!ring_buf_empty(update_ring) && num_ring_reqs < HOT_RING_REQS_THRESHOLD) {
		    page = (struct hemem_page*)ring_buf_get(update_ring);
        if (page == NULL) {
            continue;
        }
        
        #ifdef COOL_IN_PLACE
        update_current_cool_page(&cur_cool_in_dram, &cur_cool_in_nvm, page);
        #endif
        page->ring_present = false;
        num_ring_reqs++;
        histogram_update(page, page->accesses[DRAMREAD] + page->accesses[NVMREAD]);
	  }
    #else
    num_ring_reqs = 0;
    // handle hot requests from hot buffer by moving pages to hot list
    while(!ring_buf_empty(hot_ring) && num_ring_reqs < HOT_RING_REQS_THRESHOLD) {
		    page = (struct hemem_page*)ring_buf_get(hot_ring);
        if (page == NULL) {
            continue;
        }
        
        #ifdef COOL_IN_PLACE
        update_current_cool_page(&cur_cool_in_dram, &cur_cool_in_nvm, page);
        #endif
        page->ring_present = false;
        num_ring_reqs++;
        // Ignore requests to pages that have been unmapped/freed
        if(page->present == false || page->list == &dram_free_list || page->list == &nvm_free_list) {
            continue;
        }
        make_hot(page);
        //printf("hot ring, hot pages:%llu\n", num_ring_reqs);
	  }

    num_ring_reqs = 0;
    // handle cold requests from cold buffer by moving pages to cold list
    while(!ring_buf_empty(cold_ring) && num_ring_reqs < COLD_RING_REQS_THRESHOLD) {
        page = (struct hemem_page*)ring_buf_get(cold_ring);
        if (page == NULL) {
            continue;
        }

        #ifdef COOL_IN_PLACE
        update_current_cool_page(&cur_cool_in_dram, &cur_cool_in_nvm, page);
        #endif
        page->ring_present = false;
        num_ring_reqs++;
        // Ignore requests to pages that have been unmapped/freed
        if(page->present ==false || page->list == &dram_free_list || page->list == &nvm_free_list) {
            continue;
        }
        make_cold(page);
        //printf("cold ring, cold pages:%llu\n", num_ring_reqs);
    }
    #endif

    colloid_update_stats();
    
    // if(elapsed(&begin, &start) > 200.0) {
    //   // stop migrations
    //   // fprintf(colloid_log_f, "occ_local: %lf, occ_remote: %lf\n", smoothed_occ_local, smoothed_occ_remote);
    //   fprintf(colloid_log_f, "occ_local: %lf, occ_remote: %lf, best_i: %d, best_j: %d, migrated_bytes=%lu, total_accesses=%lu, freq_i=%lu, freq_j=%lu, top_freq_i=%lu, top_freq_j=%lu, inserts_local=%lf, inserts_remote=%lf, inst_occ_local=%lf, inst_occ_remote=%lf, inst_inserts_local=%lf, inst_inserts_remote=%lf\n", smoothed_occ_local, smoothed_occ_remote, 0, 0, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL, smoothed_inserts_local, smoothed_inserts_remote, occ_local, occ_remote, inserts_local, inserts_remote);
    //   goto out;
    // }

    #ifdef RATE_BETA
    beta = smoothed_inserts_local/smoothed_inserts_remote;
    #else
    beta = COLLOID_BETA;
    #endif

    // Pair finding algorithm
    #ifdef HISTOGRAM
    // TODO: Compare based on some precision threshold
    if(smoothed_occ_local == beta * smoothed_occ_remote) {
      // nothing to do
      fprintf(colloid_log_f, "equal occupancy exit\n");
      goto out;
    }
    target_delta = fabs(smoothed_occ_local - beta * smoothed_occ_remote);
    target_delta /= (smoothed_occ_local+smoothed_occ_remote);
    total_accesses = 0;
    for(int i = 0; i < MAX_HISTOGRAM_BINS; i++) {
      total_accesses += (i * dram_histogram_list[i].numentries);
      total_accesses += (i * nvm_histogram_list[i].numentries);
    }
    if(total_accesses == 0) {
      fprintf(colloid_log_f, "total_accesses=0 exit\n");
      goto out;
    }
    best_i = -1;
    best_j = -1;
    best_delta = 0.0;
    for(int i = 0; i < MAX_HISTOGRAM_BINS; i++) {
      if(i > 0 && dram_histogram_list[i].numentries == 0) {
        continue;
      }
      for(int j = 0; j < MAX_HISTOGRAM_BINS; j++) {
        if(j > 0 && nvm_histogram_list[j].numentries == 0) {
          continue;
        }
        if(smoothed_occ_local > beta * smoothed_occ_remote && i <= j) {
          continue;
        }
        if(smoothed_occ_local < beta * smoothed_occ_remote && i >= j) {
          continue;
        }
        pi = ((double)i)/((double)total_accesses);
        pj = ((double)j)/((double)total_accesses);
        if(fabs(pi - pj) <= target_delta && fabs(pi-pj) > best_delta) {
          best_i = i;
          best_j = j;
          best_delta = fabs(pi - pj);
        }
      }
    }
    if(best_i == -1 || best_j == -1) {
      // No suitable pair found; bail out;
      fprintf(colloid_log_f, "no suitable pair exit\n");
      goto out;
    }
    assert(best_i >= 0 && best_j >= 0);
    
    // Swap page pair
    migrated_bytes = 0;
    // Move local page to remote
    np = NULL;
    if(best_i == 0) {
      // No point in swapping 0 freq page if there are free pages
      np = dequeue_fifo(&dram_free_list);
    }
    if(np == NULL) {
      p = dequeue_fifo(&dram_histogram_list[best_i]);
      if(p == NULL) {
        // should ideally not happen
        fprintf(colloid_log_f, "best_i empty exit\n");
        goto out;
      }
      #ifdef COOL_IN_PLACE
      if(p == cur_cool_in_dram) {
        // TODO: this seems a bit iffy; might cause background cooling to stall
        prev_page(&dram_histogram_list[0], NULL, &cur_cool_in_dram);
      }
      #endif
      np = dequeue_fifo(&nvm_free_list);
      assert(np != NULL);
      assert(!(np->present));
      old_offset = p->devdax_offset;
      pebs_migrate_down(p, np->devdax_offset);
      np->devdax_offset = old_offset;
      np->in_dram = true;
      np->present = false;
      np->hot = false;
      for (int i = 0; i < NPBUFTYPES; i++) {
        np->accesses[i] = 0;
        np->tot_accesses[i] = 0;
      }

      // Place the migated page into right nvm histogram bin
      histogram_update(p, p->accesses[DRAMREAD] + p->accesses[NVMREAD]);
      migrated_bytes += pt_to_pagesize(p->pt);
    }
    // np is now a free dram page
    assert(np != NULL);
    
    // Move remote page to local
    if(best_j > 0) {
      p = dequeue_fifo(&nvm_histogram_list[best_j]);
      if(p == NULL) {
        // should ideally not happen
        enqueue_fifo(&dram_free_list, np);
        fprintf(colloid_log_f, "best_j empty exit\n");
        goto out;
      }
      #ifdef COOL_IN_PLACE
      if(p == cur_cool_in_nvm) {
        // TODO: this seems a bit iffy; might cause background cooling to stall
        prev_page(&nvm_histogram_list[0], NULL, &cur_cool_in_nvm);
      }
      #endif
      assert(!(np->present));
      old_offset = p->devdax_offset;
      pebs_migrate_up(p, np->devdax_offset);
      np->devdax_offset = old_offset;
      np->in_dram = false;
      np->present = false;
      np->hot = false;
      for (int i = 0; i < NPBUFTYPES; i++) {
        np->accesses[i] = 0;
        np->tot_accesses[i] = 0;
      }

      // Place the migated page into rigth nvm histogram bin
      histogram_update(p, p->accesses[DRAMREAD] + p->accesses[NVMREAD]);
      enqueue_fifo(&nvm_free_list, np);
      migrated_bytes += pt_to_pagesize(p->pt);
    } else {
      // No point in moving 0 freq page; just return np to dram free list
      enqueue_fifo(&dram_free_list, np);
    }
    fprintf(colloid_log_f, "occ_local: %lf, occ_remote: %lf, best_i: %d, best_j: %d, migrated_bytes=%lu, total_accesses=%lu\n", smoothed_occ_local, smoothed_occ_remote, best_i, best_j, migrated_bytes, total_accesses);
    #elif defined SCAN_AND_SORT
    // TODO: Compare based on some precision threshold
    if(smoothed_occ_local == beta * smoothed_occ_remote) {
      // nothing to do
      fprintf(colloid_log_f, "equal occupancy exit\n");
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
      fprintf(colloid_log_f, "total_accesses=0 exit\n");
      goto out;
    }

    // Sort frequency arrays in increasing order
    qsort(dram_page_freqs, dram_freqs_count, sizeof(struct page_freq), cmp_page_freq);
    qsort(nvm_page_freqs, nvm_freqs_count, sizeof(struct page_freq), cmp_page_freq);
  
    #ifdef COLLOID_EXPR2
    target_delta = fabs(smoothed_occ_local - beta * smoothed_occ_remote);
    target_delta /= ((1.0+beta)*(smoothed_occ_local+smoothed_occ_remote));
    #elif defined COLLOID_EXPR3
    target_delta = fabs(smoothed_occ_local - beta * smoothed_occ_remote);
    target_delta /= ((smoothed_inserts_local+smoothed_inserts_remote)*(beta*smoothed_occ_remote/smoothed_inserts_remote + smoothed_occ_local/smoothed_inserts_local));
    #elif defined COLLOID_BINSEARCH
    if(fabs(smoothed_occ_local - beta * smoothed_occ_remote) < COLLOID_DELTA*smoothed_occ_local) {
      // We are within target; don't want to migrate anything
      target_delta = 0.0;
    } else {
      cur_p = smoothed_inserts_local/(smoothed_inserts_local+smoothed_inserts_remote);
      if(smoothed_occ_local < beta * smoothed_occ_remote) {
        p_lo = cur_p;
        if(p_hi <= p_lo) {
          // reset p_hi
          p_hi = 1.0;
        }
      } else {
        p_hi = cur_p;
        if(p_lo >= p_hi) {
          // reset p_lo
          p_lo = 0.0;
        }
      }
      if(fabs(p_hi-p_lo) < COLLOID_EPSILON) {
        if(smoothed_occ_local < beta * smoothed_occ_remote) {
          p_hi = 1.0;
        } else {
          p_lo = 0.0;
        } 
      }
      target_delta = fabs((p_lo+p_hi)/2 - cur_p);
    }
    #else
    target_delta = fabs(smoothed_occ_local - beta * smoothed_occ_remote);
    target_delta /= ((smoothed_occ_local+smoothed_occ_remote));
    #endif

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
    #ifdef COLLOID_DYNAMIC_LIMIT
    dlimit = (uint64_t)(target_delta * (smoothed_inserts_local + smoothed_inserts_remote) * NUM_CHA_BOXES * 64);
    if(migrate_limit > dlimit) {
      migrate_limit = dlimit;
    }  
    #endif

    fprintf(colloid_log_f, 
    "occ_local=%lf"
    ",occ_remote=%lf"
    ",inserts_local=%lf"
    ",inserts_remote=%lf"
    ",inst_occ_local=%lf"
    ",inst_occ_remote=%lf"
    ",inst_inserts_local=%lf"
    ",inst_inserts_remote=%lf"
    ",target_delta=%lf"
    ",total_accesses=%lu"
    ",top_freq_i=%lu"
    ",top_freq_j=%lu"
    ",migrate_limit=%lu"
    ",p_lo=%lf"
    ",p_hi=%lf",
    smoothed_occ_local,
    smoothed_occ_remote,
    smoothed_inserts_local,
    smoothed_inserts_remote,
    occ_local,
    occ_remote,
    inserts_local,
    inserts_remote,
    target_delta,
    total_accesses,
    dram_page_freqs[dram_freqs_count-1].accesses,
    nvm_page_freqs[nvm_freqs_count-1].accesses,
    migrate_limit,
    p_lo,
    p_hi);

    fprintf(colloid_log_f, ",pairs=");

    for(migrated_bytes = 0; migrated_bytes < migrate_limit;) {
      // Find best pair of pages using two pointers
      best_i = -1;
      best_j = -1;
      best_delta = 0.0;
      if(smoothed_occ_local > beta * smoothed_occ_remote) {
        top = dram_page_freqs;
        top_count = dram_freqs_count;
        bottom = nvm_page_freqs;
        bottom_count = nvm_freqs_count;
      } else {
        top = nvm_page_freqs;
        top_count = nvm_freqs_count;
        bottom = dram_page_freqs;
        bottom_count = dram_freqs_count;
      }

      cur_j = 0;
      for(int i = 0; i < top_count; i++) {
        if(top[i].page == NULL) {
          continue;
        }
        pi = ((double)top[i].accesses)/((double)total_accesses);
        for(;cur_j < bottom_count; cur_j++) {
          if(bottom[cur_j].page == NULL) {
            continue;
          }
          pj = ((double)bottom[cur_j].accesses)/((double)total_accesses);
          if(pi - pj <= target_delta) {
            if(pi - pj > best_delta) {
              best_i = i;
              best_j = cur_j;
              best_delta = pi - pj;
            }
            break;
          }
        }
      }

      if(best_i == -1 || best_j == -1 || best_delta <= 0.0) {
        // No suitable pair found; bail out;
        fprintf(colloid_log_f, ",no-suitable-pair-exit,migrated_bytes=%ld,remaining_delta=%lf\n", migrated_bytes, target_delta);
        // if(tmp_dram_page != NULL) {
        //   enqueue_fifo(&dram_free_list, tmp_dram_page);
        //   tmp_dram_page = NULL;
        // }
        // if(tmp_nvm_page != NULL) {
        //   enqueue_fifo(&nvm_free_list, tmp_nvm_page);
        //   tmp_nvm_page = NULL;
        // }
        goto out;
      }
      assert(best_i >= 0 && best_j >= 0 && best_delta > 0.0);
      dram_i = (top == dram_page_freqs)?(best_i):(best_j);
      nvm_j = (top == nvm_page_freqs)?(best_i):(best_j);
      fprintf(colloid_log_f, "|best_i:%d;best_j:%d;best_delta:%lf", dram_i, nvm_j, best_delta);

      pthread_mutex_lock(&(dram_page_freqs[dram_i].page->page_lock));
      pthread_mutex_lock(&(nvm_page_freqs[nvm_j].page->page_lock));
      // the selected pair of pages could have been unmapped while we were scanning
      // if so, just bail out
      if(dram_page_freqs[dram_i].page->present == false || nvm_page_freqs[nvm_j].page->present == false) {
        pthread_mutex_unlock(&(nvm_page_freqs[nvm_j].page->page_lock));
        pthread_mutex_unlock(&(dram_page_freqs[dram_i].page->page_lock));
       fprintf(colloid_log_f, ",page-freed-exit,migrated_bytes=%ld,remaining_delta=%lf\n", migrated_bytes, target_delta);
       goto out;
      }

      // Both pages are present, and guaranteed to be so until we release their locks
      // This in-turn guarantees that they will not be unmapped during migration

      target_delta -= best_delta;

      // Swap page pair
      // migrated_bytes = 0;
      // Move local page to remote
      np = NULL;
      if(dram_page_freqs[dram_i].accesses == 0) {
        // No point in swapping 0 freq page if there are free pages
        // if(tmp_dram_page != NULL) {
        //   np = tmp_dram_page;
        //   tmp_dram_page = NULL;
        // } else {
          np = dequeue_fifo(&dram_free_list);
        // }
      }
      if(np != NULL) {
        // Page not going to be migrated; just release lock
        pthread_mutex_unlock(&(dram_page_freqs[dram_i].page->page_lock));
      } else {
        p = dram_page_freqs[dram_i].page;
        dram_page_freqs[dram_i].page = NULL;
        assert(p != NULL);
        assert(p->list != NULL);
        page_list_remove_page(p->list, p);
        #ifdef COOL_IN_PLACE
        if(p == cur_cool_in_dram) {
          cur_cool_in_dram = dram_hot_list.first;
        }
        #endif
        // if(tmp_nvm_page != NULL) {
        //   np = tmp_nvm_page;
        //   tmp_nvm_page = NULL;
        // } else {
          np = dequeue_fifo(&nvm_free_list);
        // }
        assert(np != NULL);
        assert(!(np->present));
        old_offset = p->devdax_offset;
        pebs_migrate_down(p, np->devdax_offset);
        np->devdax_offset = old_offset;
        np->in_dram = true;
        np->present = false;
        np->hot = false;
        for (int i = 0; i < NPBUFTYPES; i++) {
          np->accesses[i] = 0;
          np->tot_accesses[i] = 0;
        }

        enqueue_fifo((p->hot)?(&nvm_hot_list):(&nvm_cold_list), p);
        migrated_bytes += pt_to_pagesize(p->pt);
        // migration done; release page lock
        pthread_mutex_unlock(&(p->page_lock));
      }
      // np is now a free dram page
      assert(np != NULL);
      
      // Move remote page to local
      if(nvm_page_freqs[nvm_j].accesses > 0) {
        p = nvm_page_freqs[nvm_j].page;
        nvm_page_freqs[nvm_j].page = NULL;
        assert(p != NULL);
        assert(p->list != NULL);
        page_list_remove_page(p->list, p);
        #ifdef COOL_IN_PLACE
        if(p == cur_cool_in_nvm) {
          cur_cool_in_nvm = nvm_hot_list.first;
        }
        #endif
        assert(!(np->present));
        old_offset = p->devdax_offset;
        pebs_migrate_up(p, np->devdax_offset);
        np->devdax_offset = old_offset;
        np->in_dram = false;
        np->present = false;
        np->hot = false;
        for (int i = 0; i < NPBUFTYPES; i++) {
          np->accesses[i] = 0;
          np->tot_accesses[i] = 0;
        }

        enqueue_fifo((p->hot)?(&dram_hot_list):(&dram_cold_list), p);
        enqueue_fifo(&nvm_free_list, np);
        migrated_bytes += pt_to_pagesize(p->pt);
        // migration done; release page lock
        pthread_mutex_unlock(&(p->page_lock));
      } else {
        // No point in moving 0 freq page; release page lock and just return np to dram free list
        pthread_mutex_unlock(&(nvm_page_freqs[nvm_j].page->page_lock));
        enqueue_fifo(&dram_free_list, np);
      }
      // if(tmp_dram_page != NULL) {
      //   enqueue_fifo(&dram_free_list, tmp_dram_page);
      //   tmp_dram_page = NULL;
      // }
      // if(tmp_nvm_page != NULL) {
      //   enqueue_fifo(&nvm_free_list, tmp_nvm_page);
      //   tmp_nvm_page = NULL;
      // }
      // fprintf(colloid_log_f, "occ_local: %lf, occ_remote: %lf, best_i: %d, best_j: %d, migrated_bytes=%lu, total_accesses=%lu, freq_i=%lu, freq_j=%lu, top_freq_i=%lu, top_freq_j=%lu, inserts_local=%lf, inserts_remote=%lf, inst_occ_local=%lf, inst_occ_remote=%lf, inst_inserts_local=%lf, inst_inserts_remote=%lf\n", smoothed_occ_local, smoothed_occ_remote, dram_i, nvm_j, migrated_bytes, total_accesses, dram_page_freqs[dram_i].accesses, nvm_page_freqs[nvm_j].accesses, dram_page_freqs[dram_freqs_count-1].accesses, nvm_page_freqs[nvm_freqs_count-1].accesses, smoothed_inserts_local, smoothed_inserts_remote, occ_local, occ_remote, inserts_local, inserts_remote);
    }
    fprintf(colloid_log_f, ",hit-migration-limit,migrated_bytes=%ld,remaining_delta=%lf\n", migrated_bytes, target_delta);
    #endif

    #if !defined(HISTOGRAM) && !defined(SCAN_AND_SORT)
    #ifdef COLLOID
    if(smoothed_occ_local <= beta * smoothed_occ_remote) {
    #endif
      // move hot NVM pages to DRAM
      // delta_occ = (smoothed_occ_remote - smoothed_occ_local)/(smoothed_occ_remote);
      //migrate_limit = (uint64_t)(delta_occ * nvm_hot_list.numentries * PAGE_SIZE);
      migrate_limit = PAGE_SIZE;
      if(migrate_limit > PEBS_KSWAPD_MIGRATE_RATE) {
        migrate_limit = PEBS_KSWAPD_MIGRATE_RATE;
      }
      fprintf(colloid_log_f, "occ_local: %lf, occ_remote: %lf, nvm_hot_size: %lu, migrate_limit: %lu\n", smoothed_occ_local, smoothed_occ_remote, nvm_hot_list.numentries, migrate_limit);
      for (migrated_bytes = 0; migrated_bytes < migrate_limit;) {
        p = dequeue_fifo(&nvm_hot_list);
        if (p == NULL) {
          // nothing in NVM is currently hot -- bail out
          break;
        }

  #ifdef COOL_IN_PLACE
        if (p == cur_cool_in_nvm) {
          cur_cool_in_nvm = nvm_hot_list.first;
        }
  #endif

        if (/*(p->accesses[WRITE] < HOT_WRITE_THRESHOLD) &&*/ (p->accesses[DRAMREAD] + p->accesses[NVMREAD] < HOT_READ_THRESHOLD)) {
          // it has been cooled, need to move it into the cold list
          p->hot = false;
          enqueue_fifo(&nvm_cold_list, p); 
          continue;
        }

        for (tries = 0; tries < 2; tries++) {
          // find a free DRAM page
          np = dequeue_fifo(&dram_free_list);

          if (np != NULL) {
            assert(!(np->present));

            LOG("%lx: cold %lu -> hot %lu\t slowmem.hot: %lu, slowmem.cold: %lu\t fastmem.hot: %lu, fastmem.cold: %lu\n",
                  p->va, p->devdax_offset, np->devdax_offset, nvm_hot_list.numentries, nvm_cold_list.numentries, dram_hot_list.numentries, dram_cold_list.numentries);

            old_offset = p->devdax_offset;
            pebs_migrate_up(p, np->devdax_offset);
            np->devdax_offset = old_offset;
            np->in_dram = false;
            np->present = false;
            np->hot = false;
            for (int i = 0; i < NPBUFTYPES; i++) {
              np->accesses[i] = 0;
              np->tot_accesses[i] = 0;
            }

            enqueue_fifo(&dram_hot_list, p);
            enqueue_fifo(&nvm_free_list, np);

            migrated_bytes += pt_to_pagesize(p->pt);
            break;
          }

          // no free dram page, try to find a cold dram page to move down
          cp = dequeue_fifo(&dram_cold_list);
          if (cp == NULL) {
            // all dram pages are hot, so put it back in list we got it from
            enqueue_fifo(&nvm_hot_list, p);
            goto out;
          }
          assert(cp != NULL);

          // find a free nvm page to move the cold dram page to
          np = dequeue_fifo(&nvm_free_list);
          if (np != NULL) {
            assert(!(np->present));

            LOG("%lx: hot %lu -> cold %lu\t slowmem.hot: %lu, slowmem.cold: %lu\t fastmem.hot: %lu, fastmem.cold: %lu\n",
                  cp->va, cp->devdax_offset, np->devdax_offset, nvm_hot_list.numentries, nvm_cold_list.numentries, dram_hot_list.numentries, dram_cold_list.numentries);

            old_offset = cp->devdax_offset;
            pebs_migrate_down(cp, np->devdax_offset);
            np->devdax_offset = old_offset;
            np->in_dram = true;
            np->present = false;
            np->hot = false;
            for (int i = 0; i < NPBUFTYPES; i++) {
              np->accesses[i] = 0;
              np->tot_accesses[i] = 0;
            }

            enqueue_fifo(&nvm_cold_list, cp);
            enqueue_fifo(&dram_free_list, np);
          }
          assert(np != NULL);
        }
      }
    #ifdef COLLOID  
    } else {
      // Move hot pages from DRAM into slower tier
      // delta_occ = (smoothed_occ_local - smoothed_occ_remote)/(smoothed_occ_local);
      // migrate_limit = (uint64_t)(delta_occ * dram_hot_list.numentries * PAGE_SIZE);
      migrate_limit = PAGE_SIZE;
      if(migrate_limit > PEBS_KSWAPD_MIGRATE_RATE) {
        migrate_limit = PEBS_KSWAPD_MIGRATE_RATE;
      }
      fprintf(colloid_log_f, "occ_local: %lf, occ_remote: %lf, dram_hot_size: %lu, migrate_limit: %lu\n", smoothed_occ_local, smoothed_occ_remote, dram_hot_list.numentries, migrate_limit);

      for (migrated_bytes = 0; migrated_bytes < migrate_limit;) {
        p = dequeue_fifo(&dram_hot_list);
        if (p == NULL) {
          // nothing in DRAM is currently hot -- bail out
          break;
        }

  #ifdef COOL_IN_PLACE
        if (p == cur_cool_in_dram) {
          cur_cool_in_dram = dram_hot_list.first;
        }
  #endif

        if (/*(p->accesses[WRITE] < HOT_WRITE_THRESHOLD) &&*/ (p->accesses[DRAMREAD] + p->accesses[NVMREAD] < HOT_READ_THRESHOLD)) {
          // it has been cooled, need to move it into the cold list
          p->hot = false;
          enqueue_fifo(&dram_cold_list, p); 
          continue;
        }

        // Find free NVM page
        np = dequeue_fifo(&nvm_free_list);

        if (np != NULL) {
          assert(!(np->present));

          LOG("%lx: cold %lu -> hot %lu\t slowmem.hot: %lu, slowmem.cold: %lu\t fastmem.hot: %lu, fastmem.cold: %lu\n",
                p->va, p->devdax_offset, np->devdax_offset, nvm_hot_list.numentries, nvm_cold_list.numentries, dram_hot_list.numentries, dram_cold_list.numentries);

          old_offset = p->devdax_offset;
          pebs_migrate_down(p, np->devdax_offset);
          np->devdax_offset = old_offset;
          np->in_dram = true;
          np->present = false;
          np->hot = false;
          for (int i = 0; i < NPBUFTYPES; i++) {
            np->accesses[i] = 0;
            np->tot_accesses[i] = 0;
          }

          enqueue_fifo(&nvm_hot_list, p);
          enqueue_fifo(&dram_free_list, np);

          migrated_bytes += pt_to_pagesize(p->pt);
        } else {
          // No free NVM page; put page back in list and bail out
          enqueue_fifo(&dram_hot_list, p);
          goto out;
        }
      }

    }
    #endif
    #endif
    
    #ifdef COOL_IN_PLACE
    #ifdef HISTOGRAM
    cur_cool_in_dram = partial_cool(&dram_histogram_list[0], NULL, true, cur_cool_in_dram);
    cur_cool_in_nvm = partial_cool(&nvm_histogram_list[0], NULL, false, cur_cool_in_nvm);
    #else
    cur_cool_in_dram = partial_cool(&dram_hot_list, &dram_cold_list, true, cur_cool_in_dram);
    cur_cool_in_nvm = partial_cool(&nvm_hot_list, &nvm_cold_list, false, cur_cool_in_nvm);
    #endif
    #else
    partial_cool(&dram_hot_list, &dram_cold_list, true);
    partial_cool(&nvm_hot_list, &nvm_cold_list, false);
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
  
  scanning_thread_cpu = 63;
  migration_thread_cpu = 61;

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
  LOG_STATS("\tocc_local: [%lf]\t occ_remote: [%lf]\n", smoothed_occ_local, smoothed_occ_remote);
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
