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
#include <time.h>

#include "hemem.h"
#include "pebs.h"
#include "timer.h"
#include "spsc-ring.h"

#define MULTI_LIST


enum HOTNESS{
  COLD,
  HOT1,
  HOT2,
  HOT3,
  HOT4,
  HOT5,
  HOT6,
  NUM_HOTNESS_LEVELS
};

static struct fifo_list dram_hot_list;
static struct fifo_list dram_cold_list;
static struct fifo_list nvm_hot_list;
static struct fifo_list nvm_cold_list;
static struct fifo_list dram_free_list;
static struct fifo_list nvm_free_list;
static ring_handle_t hot_ring;
static ring_handle_t cold_ring;
static ring_handle_t free_page_ring;
static pthread_mutex_t free_page_ring_lock = PTHREAD_MUTEX_INITIALIZER;

#ifdef MULTI_LIST
// 0 is free, 1 is 0 access, 2 is 1 access, 3 is 2 access, 4 is 4 access. 
static struct fifo_list dram_lists[NUM_HOTNESS_LEVELS + 1]; 
static struct fifo_list nvm_lists[NUM_HOTNESS_LEVELS + 1];
static ring_handle_t make_hotter_ring;
static ring_handle_t make_colder_ring;

#define PEBS_SAMPLE_B_SIZE 16000000
static uint64_t pebs_samples[PEBS_SAMPLE_B_SIZE] = {0};
static uint64_t period_samples[PEBS_SAMPLE_B_SIZE] = {0};
static uint64_t pebs_sample_buffer_idx = 0;
#endif

uint64_t global_clock = 0;

uint64_t hemem_pages_cnt = 0;
uint64_t other_pages_cnt = 0;
uint64_t total_pages_cnt = 0;
uint64_t zero_pages_cnt = 0;
uint64_t good_samples = 0;
uint64_t throttle_cnt = 0;
uint64_t unthrottle_cnt = 0;
uint64_t cools = 0;
uint64_t last_pages_read_cnt = 0;

static struct perf_event_mmap_page *perf_page[PEBS_NPROCS][NPBUFTYPES];
int pfd[PEBS_NPROCS][NPBUFTYPES];

volatile bool need_cool_dram = false;
volatile bool need_cool_nvm = false;


// histogram definitions
// histogram for deciding the threshhold. bins are 0, 1, 2, 4, 8, 16, 32+
// histogram size must be a power of 2 (for bit masking)
uint64_t reading_page_histogram[HISTO_BIN_COUNT] = {0};
uint64_t reading_hot_thresh = HOT_READ_THRESHOLD;

uint64_t writing_page_histogram[HISTO_BIN_COUNT] = {0};
uint64_t writing_hot_thresh = HOT_WRITE_THRESHOLD;


#ifdef SLOW_HISTO
uint64_t read_print[HISTO_BIN_COUNT] = {0};
uint64_t write_print[HISTO_BIN_COUNT] = {0};
#else
uint64_t writing_bin_0_loc = 0;
uint64_t reading_bin_0_loc = 0;
#endif

uint64_t histo_last_global_clock = 0;
float time_taken_histo = 0.0f;

uint64_t lost_sample = 0;

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
  attr.freq = 0;

  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_ADDR | PERF_SAMPLE_PERIOD;
  attr.disabled = 0;
  //attr.inherit = 1;
  attr.exclude_kernel = 1;
  attr.exclude_hv = 1;
  attr.exclude_callchain_kernel = 1;
  attr.exclude_callchain_user = 1;
  attr.precise_ip = 1;

  assert(attr.freq == 0);

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
}

#ifdef MULTI_LIST
void make_hotter_req(struct hemem_page* page) {
  page->ring_present = true;
  ring_buf_put(make_hotter_ring, (uint64_t*)page);
}

void make_colder_req(struct hemem_page* page) {
  page->ring_present = true;
  ring_buf_put(make_colder_ring, (uint64_t*)page);
}

int access_to_index(uint64_t num) {
  if(num == 0) {
    return 0;
  }
  int ret = 64-__builtin_clzll(num);
  if(ret > NUM_HOTNESS_LEVELS-1) {
    return NUM_HOTNESS_LEVELS-1;
  }
  return ret;
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

        switch(ph->type) {
        case PERF_RECORD_SAMPLE:
            ps = (struct perf_sample*)ph;
            assert(ps != NULL);
            pebs_samples[pebs_sample_buffer_idx++ % PEBS_SAMPLE_B_SIZE] = ps->addr;
            if(ps->addr != 0) {
              __u64 pfn = ps->addr & HUGE_PFN_MASK;
            

              page = get_hemem_page(pfn);
              if (page != NULL) {
                period_samples[pebs_sample_buffer_idx % PEBS_SAMPLE_B_SIZE] = page->devdax_offset + ((page->in_dram ? 0:1)<<63);
                if (page->va != 0) {
                  
                
                  // update access counts
                  page->accesses[NVMREAD]  >>= (global_clock - page->local_clock);
                  page->accesses[DRAMREAD] >>= (global_clock - page->local_clock);
                  page->local_clock = global_clock;

                  // cool down pages
                  if (page->accesses[j] > PEBS_COOLING_THRESHOLD) {
                    cools++;
                    global_clock++;
                    need_cool_dram = true;
                    need_cool_nvm = true;
                  }


                  page->accesses[j]++;
                  page->tot_accesses[j]++; 

                  uint64_t total_accesses = page->accesses[DRAMREAD] + page->accesses[NVMREAD];
                  int new_hotness = access_to_index(total_accesses);
                  // check for hotness change and add to ring
                  if(new_hotness > page->hot) {
                    make_hotter_req(page);
                  }
                  else if(new_hotness < page->hot) {
                    make_colder_req(page);
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
            good_samples++;
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
#elif defined(DYNA_THRESH)
// TODO: move all the branching cringe into one big branch that sets up and then lets it RIP
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
  uint64_t pebs_sample_since_cool = 0;
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

        switch(ph->type) {
        case PERF_RECORD_SAMPLE:
            ps = (struct perf_sample*)ph;
            assert(ps != NULL);
            if(ps->addr != 0) {
              __u64 pfn = ps->addr & HUGE_PFN_MASK;
            
              page = get_hemem_page(pfn);
              if (page != NULL) {
                if (page->va != 0) {
		  
		            // Cool pages BEFORE we increment
		            // FIXME: reads can cool writes and writes can cool reads.
		            // no enforcement of which access cools off the pages and then the next page access gets the cool.
                if (j == DRAMREAD || j == NVMREAD) {		    
                  uint64_t shift_amount = read_global_clock - page->local_clock;
                  if(shift_amount >= 64) {
                    shift_amount = 63;
                  }
                  page->accesses[NVMREAD]  >>= (shift_amount);
                  page->accesses[DRAMREAD] >>= (shift_amount);
                  page->local_clock = read_global_clock;		    
                  page->cur_read_bin = shift_amount > page->cur_read_bin ? 0 : page->cur_read_bin - shift_amount;
                  
                }
                else if (j == WRITE) {
                  uint64_t shift_amount = write_global_clock - page->local_clock;
                  if(shift_amount >= 64) {
                    shift_amount = 63;
                  }
                  page->accesses[WRITE] >>= (shift_amount);
                  page->local_clock = write_global_clock;
                  page->cur_write_bin = shift_amount > page->cur_write_bin ? 0 : page->cur_write_bin - shift_amount;
                  
                }
                else {
                  assert(false && "update case fail.\n");
                }

#ifndef SAMP_COOLING
	          	  if (page->accesses[j] > PEBS_COOLING_THRESHOLD) {
#else
		            if (pebs_sample_since_cool >= SAMPLE_COOLING_NUM) {
#endif
                  pebs_sample_since_cool = 0;
                  cools++;
                  need_cool_dram = true;
                  need_cool_nvm = true;

                  int new_bin_0_loc = 0;
  #ifndef SAMP_COOLING
                  if (j == DRAMREAD || j == NVMREAD) {
  #endif
                    // cooling reads
                    read_global_clock++;
                    page->accesses[NVMREAD]  >>= (1);
                    page->accesses[DRAMREAD] >>= (1);
                    page->local_clock = read_global_clock;
                    page->cur_read_bin = 1 > page->cur_read_bin ? 0 : page->cur_read_bin - 1;
                    
                    new_bin_0_loc = (reading_bin_0_loc + 1) & (HISTO_BIN_COUNT-1);
                    reading_page_histogram[new_bin_0_loc] += reading_page_histogram[reading_bin_0_loc];
                    reading_page_histogram[reading_bin_0_loc] = 0;
                    reading_bin_0_loc = new_bin_0_loc;
#ifndef SAMP_COOLING
                  }
                  else if (j == WRITE) {
#endif
                    // cooling writes
                    write_global_clock++;
                    page->accesses[WRITE] >>= (1);
                    page->local_clock = write_global_clock;
                    page->cur_write_bin = 1 > page->cur_write_bin ? 0 : page->cur_write_bin - 1;
                    
                    new_bin_0_loc = (writing_bin_0_loc + 1) & (HISTO_BIN_COUNT-1);
                    writing_page_histogram[new_bin_0_loc] += writing_page_histogram[writing_bin_0_loc];
                    writing_page_histogram[writing_bin_0_loc] = 0;
                    writing_bin_0_loc = new_bin_0_loc;
#ifndef SAMP_COOLING
                  }
                  else {
                    assert(false && "Cooling case fail.\n");
                  }
#endif		    
                }
                pebs_sample_since_cool++;

                // we assume the page is up to date in terms of cooling by this point
                uint64_t acc_temp = 0;
                uint64_t current_histo_bin0 = 0;
                size_t   prev_bin = 0;
                
                if (j == DRAMREAD || j == NVMREAD) {
                  current_histo_bin0 = reading_bin_0_loc;
                  acc_temp = page->accesses[DRAMREAD] + page->accesses[NVMREAD];
                  assert(page->local_clock == read_global_clock);
                  prev_bin = ((page->cur_read_bin + current_histo_bin0) & (HISTO_BIN_COUNT-1));
                }
                else if (j == WRITE) {
                  current_histo_bin0 = writing_bin_0_loc;
                  acc_temp = page->accesses[WRITE];
                  assert(page->local_clock == write_global_clock);
                  prev_bin = ((page->cur_write_bin + current_histo_bin0) & (HISTO_BIN_COUNT-1));
                }
                else {
                  assert(false && "prev_bin case fail.\n");
                }
                
                page->accesses[j]++;
                page->tot_accesses[j]++;
                
                /* int log2fast = 64-__builtin_clzll(acc_temp); */
                /* log2fast = log2fast >= HISTO_BIN_COUNT ? 7 : log2fast; */
                /* prev_bin = acc_temp != 0 ? ((log2fast + current_histo_bin0) & (HISTO_BIN_COUNT-1)) : current_histo_bin0; */

                acc_temp++;
                size_t next_bin = 0;
                int log2fast = 64-__builtin_clzll(acc_temp);
                log2fast = log2fast >= HISTO_BIN_COUNT ? 7 : log2fast;
                next_bin = acc_temp != 0 ? ((log2fast + current_histo_bin0) & (HISTO_BIN_COUNT-1)) : current_histo_bin0;
                  
                if (page->accesses[WRITE] >= writing_hot_thresh) {
                  if (!page->hot || !page->ring_present) {
                      make_hot_request(page);
                  }
                }
                else if (page->accesses[DRAMREAD] + page->accesses[NVMREAD] >= reading_hot_thresh) {
                  if (!page->hot || !page->ring_present) {
                      make_hot_request(page);
                  }
                }
                else if ((page->accesses[WRITE] < writing_hot_thresh) && (page->accesses[DRAMREAD] + page->accesses[NVMREAD] < reading_hot_thresh)) {
                  if (page->hot || !page->ring_present) {
                      make_cold_request(page);
                  }
                }		  
                  
                if (j == DRAMREAD || j == NVMREAD) { 
                  assert(reading_page_histogram[prev_bin] != 0);
                  reading_page_histogram[prev_bin] -= 1;
                  reading_page_histogram[next_bin] += 1;
                  page->cur_read_bin = log2fast;
                }
                else if (j == WRITE) {
                  assert(writing_page_histogram[prev_bin] != 0);
                  writing_page_histogram[prev_bin] -= 1; 
                  writing_page_histogram[next_bin] += 1;
                  page->cur_write_bin = log2fast;
                }
                else {
                  assert(false && "moving bins case fail.\n");
                } 
        
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

#else

void *pebs_scan_thread()
{
  cpu_set_t cpuset;
  pthread_t thread;

  thread = pthread_self();
  CPU_ZERO(&cpuset);
  CPU_SET(24, &cpuset);
  int s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (s != 0)
  {
    perror("pthread_setaffinity_np");
    assert(0);
  }

  for (;;)
  {
    for (int i = 0; i < PEBS_NPROCS; i++)
    {
      for (int j = 0; j < NPBUFTYPES; j++)
      {
        char *pbuf = (char *)p + p->data_offset;

        __sync_synchronize();

        if (p->data_head == p->data_tail)
        {
          continue;
        }

        struct perf_event_header *ph = (void *)(pbuf + (p->data_tail % p->data_size));
        struct perf_sample *ps;
        struct hemem_page *page;
        if (ph->size == 0)
        {
          continue;
        }

        switch (ph->type)
        {
        case PERF_RECORD_SAMPLE:
          ps = (struct perf_sample *)ph;
          assert(ps != NULL);
          if (ps->addr != 0)
          {
            __u64 pfn = ps->addr & HUGE_PFN_MASK;

            page = get_hemem_page(pfn);
            if (page != NULL)
            {
              if (page->va != 0)
              {
                page->accesses[j]++;
                page->tot_accesses[j]++;
                if (page->accesses[WRITE] >= HOT_WRITE_THRESHOLD)
                {
                  if (!page->hot && !page->ring_present)
                  {
                    make_hot_request(page);
                  }
                }
                else if (page->accesses[DRAMREAD] + page->accesses[NVMREAD] >= HOT_READ_THRESHOLD)
                {
                  if (!page->hot && !page->ring_present)
                  {
                    make_hot_request(page);
                  }
                }
                else if ((page->accesses[WRITE] < HOT_WRITE_THRESHOLD) && (page->accesses[DRAMREAD] + page->accesses[NVMREAD] < HOT_READ_THRESHOLD))
                {
                  if (page->hot && !page->ring_present)
                  {
                    make_cold_request(page);
                  }
                }
                page->accesses[DRAMREAD] >>= (global_clock - page->local_clock);
                page->accesses[NVMREAD] >>= (global_clock - page->local_clock);
                page->accesses[WRITE] >>= (global_clock - page->local_clock);
                page->local_clock = global_clock;
                if (page->accesses[j] > PEBS_COOLING_THRESHOLD)
                {
                  global_clock++;
                  cools++;
                  need_cool_dram = true;
                  need_cool_nvm = true;
                  cools++;
                }
              }
              hemem_pages_cnt++;
            }
            else
            {
              other_pages_cnt++;
            }

            total_pages_cnt++;
          }
          else
          {
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
#endif

static void pebs_migrate_down(struct hemem_page *page, uint64_t offset)
{
  struct timeval start, end;

  gettimeofday(&start, NULL);

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

  page->migrating = true;
  hemem_wp_page(page, true);
  hemem_migrate_up(page, offset);
  page->migrating = false;

  gettimeofday(&end, NULL);
  LOG_TIME("migrate_up: %f s\n", elapsed(&start, &end));
}

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
      assert(page->list == &dram_cold_list);
    }
    else {
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
    assert(page->list == &nvm_hot_list);
    page_list_remove_page(&nvm_hot_list, page);
    page->hot = false;
    enqueue_fifo(&nvm_cold_list, page);
  }
}

#ifdef MULTI_LIST
void change_page_list(struct hemem_page* page, int new_hotness) {
  assert(page != NULL);
  assert(page->va != 0);

  if (page->hot == new_hotness) {
    if (page->in_dram) {
      assert(page->list == &dram_lists[new_hotness]);
    }
    else {
      assert(page->list == &nvm_lists[new_hotness]);
    }
    return;
  }

  if (page->in_dram) {
    assert(page->list == &dram_lists[page->hot]);
    page_list_remove_page(page->list, page);
    page->hot = new_hotness;
    enqueue_fifo(&dram_lists[new_hotness], page);
  }
  else {
    assert(page->list == &nvm_lists[page->hot]);
    page_list_remove_page(page->list, page);
    page->hot = new_hotness;
    enqueue_fifo(&nvm_lists[new_hotness], page);
  }
}
#endif

static struct hemem_page* start_dram_page = NULL;
static struct hemem_page* start_nvm_page = NULL;

#ifdef COOL_IN_PLACE
struct hemem_page* partial_cool(struct fifo_list *hot, struct fifo_list *cold, bool dram, struct hemem_page* current)
{
  struct hemem_page *p;
  uint64_t tmp_accesses[NPBUFTYPES];

  if (dram && !need_cool_dram) {
    if (current != NULL)
      assert(current->list == hot);
    return current;
  }
  if (!dram && !need_cool_nvm) {
    if (current != NULL)
      assert(current->list == hot);
    return current;
  }

  if (start_dram_page == NULL && dram) {
      start_dram_page = hot->last;
  }

  if (start_nvm_page == NULL && !dram) {
      start_nvm_page = hot->last;
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

#if defined(MULTI_LIST)
    tmp_accesses[NVMREAD] = p->accesses[NVMREAD] >> (global_clock - p->local_clock);
    tmp_accesses[DRAMREAD] = p->accesses[DRAMREAD] >> (global_clock - p->local_clock);
#else
    for (int j = 0; j < NPBUFTYPES; j++) {
        tmp_accesses[j] = p->accesses[j] >> (global_clock - p->local_clock);
    }
#endif

    if ((tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD] < HOT_READ_THRESHOLD)) {
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

    if (!p->hot) {
        current = p->next;
        if (current != NULL)
          assert(current->list == hot);
        page_list_remove_page(hot, p);
        enqueue_fifo(cold, p);
    }
    else {
        current = p;
    }
  }
  if (current != NULL) {
    assert(current->list == &dram_hot_list || current->list == &nvm_hot_list);
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

#if defined(MULTI_LIST)
    tmp_accesses[WRITE] = p->accesses[WRITE] >> (global_clock - p->local_clock);
    tmp_accesses[NVMREAD] = p->accesses[NVMREAD] >> (global_clock - p->local_clock);
    tmp_accesses[DRAMREAD] = p->accesses[DRAMREAD] >> (global_clock - p->local_clock);
#else
    for (int j = 0; j < NPBUFTYPES; j++) {
        tmp_accesses[j] = p->accesses[j] >> (global_clock - p->local_clock);
    }
#endif

    if ((tmp_accesses[WRITE] < HOT_WRITE_THRESHOLD) && (tmp_accesses[DRAMREAD] + tmp_accesses[NVMREAD] < HOT_READ_THRESHOLD)) {
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

#ifdef MULTI_LIST
// we will never finish cooling....
// need to fix that -Kayvan
bool partial_cool_peek_and_move(bool dram, struct hemem_page** cur_hotlist_index, int* list_index)
{
  // to keep track of if we finished up or not.
  static struct hemem_page* starting_dram_page = NULL;
  static int starting_list_dram = 0;
  static struct hemem_page* starting_nvm_page = NULL;
  static int starting_list_nvm = 0;

  uint64_t tmp_accesses[NPBUFTYPES];
  struct hemem_page *p = NULL;
  int cur_list_index = *list_index;

  bool ret = true;

  if (dram && !need_cool_dram) {
      return true;
  }
  if (!dram && !need_cool_nvm) {
      return true;
  }

  // if this is the first time we have done a cool. then set the starts. 
  if (starting_dram_page == NULL && dram) {
      starting_dram_page = dram_lists[NUM_HOTNESS_LEVELS-1].last;
      starting_list_dram = NUM_HOTNESS_LEVELS-1;
  }
  if (starting_nvm_page == NULL && !dram) {
      starting_nvm_page = nvm_lists[NUM_HOTNESS_LEVELS-1].last;
      starting_list_nvm = NUM_HOTNESS_LEVELS-1;
  }

  // if we don't have a bookmark on the pages then we can just start from the top!
  if(cur_list_index < 1) {
    cur_list_index = NUM_HOTNESS_LEVELS-1;
  }

  for (int j = 0; j < COOLING_PAGES; j++) {
    // iterate the pages. 
    if(dram) {
      next_page(&dram_lists[cur_list_index], *cur_hotlist_index, &p);
    }
    else {
      next_page(&nvm_lists[cur_list_index], *cur_hotlist_index, &p);
    }

    if(p == NULL) {
      // done with pages in this list! yay!
      // move to the next list.
      if(cur_list_index > 1) {
        cur_list_index--;
        *cur_hotlist_index = NULL;
        (*list_index)--;
        continue;

      } else {

        // no next list. is done.
        if(dram) {
          starting_dram_page = NULL;
          need_cool_dram = false;
          *cur_hotlist_index = NULL;
          (*list_index) = 0;
          return true;
        } else {
          starting_nvm_page = NULL;
          need_cool_nvm = false;
          *cur_hotlist_index = NULL;
          (*list_index) = 0;
          return true;
        }
      }
      break;
    }

    uint64_t old_hotness = p->hot;
    if (dram) {
      assert(p->in_dram);
    }
    else {
      assert(!p->in_dram);
    }

    tmp_accesses[NVMREAD] = p->accesses[NVMREAD] >> (global_clock - p->local_clock);
    tmp_accesses[DRAMREAD] = p->accesses[DRAMREAD] >> (global_clock - p->local_clock);

    p->hot = access_to_index(tmp_accesses[DRAMREAD] + tmp_accesses[DRAMREAD]);

    // if we got cooled then cool. duh.
    if (old_hotness > p->hot) {
        *cur_hotlist_index = p->next;
        page_list_remove_page(p->list, p);
        if(dram) {
          enqueue_fifo(&(dram_lists[p->hot]), p);
        }
        else {
          enqueue_fifo(&(nvm_lists[p->hot]), p);
        }
    }
    else {
        *cur_hotlist_index = p;
    }
  }

  return false;
}

#else
struct hemem_page* partial_cool_peek_and_move(struct fifo_list *hot, struct fifo_list *cold, bool dram, struct hemem_page* current)
{
  struct hemem_page *p;
  uint64_t tmp_accesses[NPBUFTYPES];

  if (dram && !need_cool_dram) {
      return current;
  }
  if (!dram && !need_cool_nvm) {
      return current;
  }

  if (start_dram_page == NULL && dram) {
      start_dram_page = hot->last;
  }

  if (start_nvm_page == NULL && !dram) {
      start_nvm_page = hot->last;
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

#if defined(DYNA_THRESH)
    tmp_accesses[WRITE] = p->accesses[WRITE] >> (write_global_clock - p->local_clock);
    tmp_accesses[NVMREAD] = p->accesses[NVMREAD] >> (read_global_clock - p->local_clock);
    tmp_accesses[DRAMREAD] = p->accesses[DRAMREAD] >> (read_global_clock - p->local_clock);
#else
    for (int i = 0; i < NPBUFTYPES; i++) {
      tmp_accesses[i] = p->accesses[i] >> (global_clock - p->local_clock);
    }
#endif

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
#endif

#ifdef MULTI_LIST
// check if page is any of our partial cooling indexes. 
// if it is one of those indexes then move to the next page in the list. 
// really we should be able to return after the first match. -Kayvan
void update_current_cool_page(struct hemem_page** cur_cool_in_dram, struct hemem_page** cur_cool_in_nvm, struct hemem_page* page)
{
  if (page == NULL) {
    return;
  }

  if (page == *cur_cool_in_dram) {
    assert(page->list == (*cur_cool_in_dram)->list);
    next_page(page->list, page, cur_cool_in_dram);
    if((*cur_cool_in_dram) != NULL) 
      assert((*cur_cool_in_dram)->list == page->list);
  }
  if (page == *cur_cool_in_nvm) {
    assert(page->list == (*cur_cool_in_nvm)->list);
    next_page(page->list, page, cur_cool_in_nvm);
    if ((*cur_cool_in_nvm) != NULL)
      assert((*cur_cool_in_nvm)->list == page->list);
  }
}
#elif defined(COOL_IN_PLACE)
void update_current_cool_page(struct hemem_page** cur_cool_in_dram, struct hemem_page** cur_cool_in_nvm, struct hemem_page* page)
{
  if (page == NULL) {
    return;
  }

  if (page == *cur_cool_in_dram) {
    assert(page->list == &dram_hot_list);
    next_page(page->list, page, cur_cool_in_dram);
    if((*cur_cool_in_dram) != NULL) 
      assert((*cur_cool_in_dram)->list == &dram_hot_list);
  }
  if (page == *cur_cool_in_nvm) {
    assert(page->list == &nvm_hot_list);
    next_page(page->list, page, cur_cool_in_nvm);
    if (*cur_cool_in_nvm != NULL)
      assert((*cur_cool_in_nvm)->list == &nvm_hot_list);
  }
  if(*cur_cool_in_nvm != NULL) {
    assert((*cur_cool_in_nvm)->list == &nvm_hot_list);
  }
  if(*cur_cool_in_dram != NULL) {
    assert((*cur_cool_in_dram)->list == &dram_hot_list);
  }
}
#endif

#ifndef SLOW_HISTO
void log_histogram() {
  int wsum = 0;
  int rsum = 0;
  int index = writing_bin_0_loc;

  LOG_STATS("%s", "Writing Histogram: ");
  do {
    LOG_STATS("%ld, ", writing_page_histogram[index]);
    wsum += writing_page_histogram[index];
    index = ((index + 1) & (HISTO_BIN_COUNT-1));
  } while(index != ((writing_bin_0_loc) & (HISTO_BIN_COUNT-1)));

  index = reading_bin_0_loc;
  LOG_STATS("%s", "Reading Histogram: ");
  do {
    LOG_STATS("%ld, ", reading_page_histogram[index]);
    rsum += reading_page_histogram[index];
    index = ((index + 1) & (HISTO_BIN_COUNT-1));
  } while(index != ((reading_bin_0_loc) & (HISTO_BIN_COUNT-1))); 
  
  LOG_STATS(" Writing_Bin_0: [%ld], Reading_Bin_0: [%ld]\nwriting Sum: [%d], reading Sum: [%d]\n", writing_bin_0_loc, reading_bin_0_loc, wsum, rsum);
}


#define READ_MIN 4
#define WRITE_MIN 4
int64_t timeSinceLast = 0;
#define PERC_IN_DRAM 9/10

int update_thresholds() {
  int64_t total_pages_dram = dram_hot_list.numentries + dram_cold_list.numentries + dram_free_list.numentries;

  total_pages_dram = total_pages_dram * PERC_IN_DRAM; 
  
  int64_t shift_amount = ((HISTO_BIN_COUNT-1) + reading_bin_0_loc) & (HISTO_BIN_COUNT-1);
  while(total_pages_dram > 0 && shift_amount != reading_bin_0_loc) {
#ifdef WEIGHTED
    total_pages_dram -= (reading_page_histogram[shift_amount]) * (1<<shift_amount);
#else
    total_pages_dram -= (reading_page_histogram[shift_amount]);
#endif
    shift_amount = (shift_amount-1) & (HISTO_BIN_COUNT-1);
  }
  
  if(shift_amount != reading_bin_0_loc) {
    reading_hot_thresh = 1 << (((shift_amount - reading_bin_0_loc) & (HISTO_BIN_COUNT-1)));
  }
  else{
    reading_hot_thresh = 2;
  }
  if(reading_hot_thresh < 2) {
    reading_hot_thresh = 2;
  }
    
  total_pages_dram = dram_hot_list.numentries + dram_cold_list.numentries + dram_free_list.numentries;

  total_pages_dram = total_pages_dram * PERC_IN_DRAM;
  
  shift_amount = ((HISTO_BIN_COUNT-1) + writing_bin_0_loc) & (HISTO_BIN_COUNT-1);
  while(total_pages_dram > 0 && shift_amount != writing_bin_0_loc) {
#ifdef WEIGHTED
    total_pages_dram -= (writing_page_histogram[shift_amount]) * (1<<shift_amount);
#else
    total_pages_dram -= (writing_page_histogram[shift_amount]);
#endif
    shift_amount = (shift_amount-1) & (HISTO_BIN_COUNT-1);
  }
    
  if(shift_amount != writing_bin_0_loc) {
    writing_hot_thresh = 1 << (((shift_amount - writing_bin_0_loc) & (HISTO_BIN_COUNT-1)));
  }
  else{
    writing_hot_thresh = 1;
  }
  if(writing_hot_thresh < 2) {
    writing_hot_thresh = 2;
  }
  return 0;
}
#endif

#ifdef SLOW_HISTO
void log_histogram() {
  int wsum = 0;
  int rsum = 0;
  int index = 0;

  LOG_STATS("%s", "Writing Histogram: ");
  while(index < HISTO_BIN_COUNT) {
    LOG_STATS("%ld, ", write_print[index]);
    wsum += write_print[index];
    index = ((index + 1));
  }

  index = 0;
  LOG_STATS("%s", "Reading Histogram: ");
  while(index < HISTO_BIN_COUNT) {
    LOG_STATS("%ld, ", read_print[index]);
    rsum += read_print[index];
    index = ((index + 1));
  }
  
  LOG_STATS(" \nwriting Sum: [%d], reading Sum: [%d]\n", wsum, rsum);
}

int update_histogram(uint64_t* histo, bool is_read)
{
  // get the "first page" of the list
  // actually the last page
  struct hemem_page* cur_page = NULL;
  int index = 0;
  int pages_read = 0;
  uint64_t temp_histo[HISTO_BIN_COUNT] = {0};
  static struct fifo_list* all_list[4] = {&dram_hot_list,
    &dram_cold_list,
    &nvm_hot_list,
    &nvm_cold_list};
  static struct fifo_list* cur_list = NULL;

  for(int i = 0; i < 4; i++) {
    cur_list = all_list[i];
    cur_page = next_page(cur_list, NULL);
    
    while(cur_page != NULL) {
      index = 0;

      // get the stupid log_2 
      int n_accesses;
      if(is_read) {
	n_accesses = cur_page->accesses[DRAMREAD] + cur_page->accesses[NVMREAD];
      }
      else {
	n_accesses = cur_page->accesses[WRITE];
      }

      index = access_to_index(n_accesses);

      // increment that bin
      temp_histo[index] = temp_histo[index] + 1.0;

      // go to next page
      cur_page = next_page(cur_list, cur_page);
      pages_read++;
    }
  }

  for(int i = 0; i < HISTO_BIN_COUNT; i++) {
    histo[i] = temp_histo[i];
  }
  return pages_read;
}

// this actually updates the thresholds
int update_thresholds() { 
  int pages_read = 0;
  // reset the histograms
  for(int i = 0; i < HISTO_BIN_COUNT; i++) {
    reading_page_histogram[i] = 0;
    writing_page_histogram[i] = 0;
  }
  
  // update all the read pages
  pages_read += update_histogram(reading_page_histogram, true);

  // update all the write page
  pages_read += update_histogram(writing_page_histogram, false);
  
  assert(sizeof(writing_page_histogram[0]) == sizeof(write_print[0]));
  assert(sizeof(reading_page_histogram[0]) == sizeof(read_print[0]));
  for (int i = 0; i < HISTO_BIN_COUNT; i++) {
    read_print[i] = reading_page_histogram[i];
    write_print[i] = writing_page_histogram[i];
  }
  
  
  int total_pages_dram = dram_hot_list.numentries + dram_cold_list.numentries + dram_free_list.numentries;
  int shift_amount = 5;
  while(total_pages_dram > 0 && shift_amount >= 0) {
    total_pages_dram -= reading_page_histogram[shift_amount];
    shift_amount--;
  }
  if(shift_amount < 0 && total_pages_dram >= 0) {
    reading_hot_thresh = 1;
  }
  else if(shift_amount < 0) {
    reading_hot_thresh = 1;
  }
  else {
    reading_hot_thresh = 1 << shift_amount;
  }
  
  total_pages_dram = dram_hot_list.numentries + dram_cold_list.numentries + dram_free_list.numentries;
  shift_amount = 5;
  while(total_pages_dram > 0 && shift_amount >= 0) {
    total_pages_dram -= writing_page_histogram[shift_amount];
    shift_amount--;
  }
  if(shift_amount < 0 && total_pages_dram >= 0) {
    writing_hot_thresh = 1;
  }
  else if(shift_amount < 0) {
    writing_hot_thresh = 1;
  }
  else {
    writing_hot_thresh = 1 << shift_amount;
  }
  
  assert(writing_hot_thresh > 0);
  assert(reading_hot_thresh > 0);
  
  return pages_read;
}
#endif

#ifdef MULTI_LIST

struct hemem_page* find_cadidate_nvm_page() {
  struct hemem_page* p;
  for(int i = NUM_HOTNESS_LEVELS-1; i >= 0; i--) {
    p = (struct hemem_page*)dequeue_fifo(&(nvm_lists[i]));
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
    p = (struct hemem_page*)dequeue_fifo(&(dram_lists[i]));
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
  int num_ring_reqs;
  struct hemem_page* page = NULL;
  struct hemem_page* cur_dram_cooling_index = NULL;
  int dram_list_index = 0;
  struct hemem_page* cur_nvm_cooling_index = NULL;
  int nvm_list_index = 0;
  struct timeval start_histo, end_histo;
  
  thread = pthread_self();
  CPU_ZERO(&cpuset);
  CPU_SET(MIGRATION_THREAD_CPU, &cpuset);
  int s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (s != 0) {
    perror("pthread_setaffinity_np");
    assert(0);
  }

  for (;;) {    
    continue;
    // put pages that got freed back onto their free lists
    while(!ring_buf_empty(free_page_ring)) {
        struct fifo_list *list;
        page = (struct hemem_page*)ring_buf_get(free_page_ring);
        if (page == NULL) {
            continue;
        }
        
        list = page->list;
        assert(list != NULL);
        #ifdef COOL_IN_PLACE
        update_current_cool_page(&cur_dram_cooling_index, &cur_nvm_cooling_index, page);
        #endif
        page_list_remove_page(list, page);
        if (page->in_dram) {
          enqueue_fifo(&dram_free_list, page);
        }
        else {
          enqueue_fifo(&nvm_free_list, page);
        }
    }

    // move a page from the ring to where it needs to go. since we enforce a hotter and colder ring then we can 
    // only check above. This is something I want to check with amanda about first. - Kayvan
    num_ring_reqs = 0;
    while(!ring_buf_empty(make_hotter_ring) && num_ring_reqs < HOT_RING_REQS_THRESHOLD) {
		    page = (struct hemem_page*)ring_buf_get(make_hotter_ring);
        if (page == NULL) {
            continue;
        }
        
        #ifdef COOL_IN_PLACE
        update_current_cool_page(&cur_dram_cooling_index, &cur_nvm_cooling_index, page);
        #endif
        page->ring_present = false;
        num_ring_reqs++;
        change_page_list(page, access_to_index(page->accesses[DRAMREAD] + page->accesses[NVMREAD]));
    }
    num_ring_reqs = 0;
    while(!ring_buf_empty(make_colder_ring) && num_ring_reqs < COLD_RING_REQS_THRESHOLD) {
		    page = (struct hemem_page*)ring_buf_get(make_colder_ring);
        if (page == NULL) {
            continue;
        }
        
        #ifdef COOL_IN_PLACE
        update_current_cool_page(&cur_dram_cooling_index, &cur_nvm_cooling_index, page);
        #endif
        page->ring_present = false;
        num_ring_reqs++;
        change_page_list(page, access_to_index(page->accesses[DRAMREAD] + page->accesses[NVMREAD]));
    }
    
    // move each hot NVM page to DRAM
    for (migrated_bytes = 0; migrated_bytes < PEBS_KSWAPD_MIGRATE_RATE;) {
      p = find_cadidate_nvm_page();
      if(p == NULL) {
        // didn't find hot page to move up. bail.
        break;
      }

      #ifdef COOL_IN_PLACE
      update_current_cool_page(&cur_dram_cooling_index, &cur_nvm_cooling_index, page); // never set page here? wtf?
      #endif

      if (access_to_index(p->accesses[DRAMREAD] + p->accesses[NVMREAD]) < p->hot) {
        // it has been cooled, need to move it into the cold list
        p->hot = access_to_index(p->accesses[DRAMREAD] + p->accesses[NVMREAD]);
        enqueue_fifo(&nvm_lists[p->hot], p); 
        continue;
      }

      for (tries = 0; tries < 2; tries++) {
        // find a free DRAM page
        np = dequeue_fifo(&dram_free_list);

        if (np != NULL) {
          assert(!(np->present));

          #ifdef COOL_IN_PLACE
          update_current_cool_page(&cur_dram_cooling_index, &cur_nvm_cooling_index, np);
          #endif

          LOG("%lx: cold %lu -> hot %lu\t slowmem.hot: %lu, slowmem.cold: %lu\t fastmem.hot: %lu, fastmem.cold: %lu\n",
                p->va, p->devdax_offset, np->devdax_offset, nvm_hot_list.numentries, nvm_cold_list.numentries, dram_hot_list.numentries, dram_cold_list.numentries);

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

          enqueue_fifo(&(dram_lists[p->hot]), p);
          enqueue_fifo(&nvm_free_list, np);

          migrated_bytes += pt_to_pagesize(p->pt);
          break;
        }

        // no free dram page, try to find a cold dram page to move down
        cp = find_dram_victim(p->hot);
        if(cp == NULL) {
          // no victim
          enqueue_fifo(&nvm_lists[p->hot], p);
          goto out;
        }
        assert(cp != NULL);

        #ifdef COOL_IN_PLACE
        update_current_cool_page(&cur_dram_cooling_index, &cur_nvm_cooling_index, cp);
        #endif 
         
        // find a free nvm page to move the cold dram page to
        np = dequeue_fifo(&nvm_free_list);
        if (np != NULL) {
          assert(!(np->present));

          #ifdef COOL_IN_PLACE
          update_current_cool_page(&cur_dram_cooling_index, &cur_nvm_cooling_index, np);
          #endif 

          LOG("%lx: hot %lu -> cold %lu\t slowmem.hot: %lu, slowmem.cold: %lu\t fastmem.hot: %lu, fastmem.cold: %lu\n",
                cp->va, cp->devdax_offset, np->devdax_offset, nvm_hot_list.numentries, nvm_cold_list.numentries, dram_hot_list.numentries, dram_cold_list.numentries);

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
          enqueue_fifo(&nvm_lists[cp->hot], cp);
          enqueue_fifo(&dram_free_list, np);
        }
        assert(np != NULL);
      }
    }
    
    // move pages down that havent been accessed for a while.
    // needed for pages that were once hot and now get no accesses. 
    // Since there are no accesses PEBS thread will never request they go cold.
    // Thus we iterate te hot and warm list to move pages down to the cold list.
    #ifdef COOL_IN_PLACE
    partial_cool_peek_and_move(true, &cur_dram_cooling_index, &dram_list_index);
    partial_cool_peek_and_move(false, &cur_nvm_cooling_index, &nvm_list_index);
    #else
    partial_cool(&dram_hot_list, &dram_cold_list, true);
    partial_cool(&nvm_hot_list, &nvm_cold_list, false);
    #endif
 

out:
#if defined(DYNA_THRESH) || defined(SLOW_HISTO)
    gettimeofday(&start_histo, NULL);
    last_pages_read_cnt = update_thresholds();
    gettimeofday(&end_histo, NULL);       
    time_taken_histo = elapsed(&start_histo, &end_histo);
#endif    
    LOG_TIME("migrate: %f s\n", elapsed(&start, &end));
  }

  return NULL;
}
#else
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
  #ifdef COOL_IN_PLACE
  struct hemem_page* cur_cool_in_dram  = NULL;
  struct hemem_page* cur_cool_in_nvm = NULL;
  #endif

  thread = pthread_self();
  CPU_ZERO(&cpuset);
  CPU_SET(MIGRATION_THREAD_CPU, &cpuset);
  int s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (s != 0) {
    perror("pthread_setaffinity_np");
    assert(0);
  }

  for (;;) {
    // free pages using free page ring buffer
    while(!ring_buf_empty(free_page_ring)) {
        struct fifo_list *list;
        page = (struct hemem_page*)ring_buf_get(free_page_ring);
        if (page == NULL) {
            continue;
        }
        
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
        make_cold(page);
        //printf("cold ring, cold pages:%llu\n", num_ring_reqs);
    }
    
    // move each hot NVM page to DRAM
    for (migrated_bytes = 0; migrated_bytes < PEBS_KSWAPD_MIGRATE_RATE;) {
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

          assert(p->hot);
          enqueue_fifo(&dram_hot_list, p);
          enqueue_fifo(&nvm_free_list, np);

          migrated_bytes += pt_to_pagesize(p->pt);
          break;
        }

        // no free dram page, try to find a cold dram page to move down
        cp = dequeue_fifo(&dram_cold_list);
        if (cp == NULL) {
          // all dram pages are hot, so put it back in list we got it from
          assert(p->hot);
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

          assert(!cp->hot);
          assert(!np->hot);
          enqueue_fifo(&nvm_cold_list, cp);
          enqueue_fifo(&dram_free_list, np);
        }
        assert(np != NULL);
      }
    }

    #ifdef COOL_IN_PLACE
    cur_cool_in_dram = partial_cool(&dram_hot_list, &dram_cold_list, true, cur_cool_in_dram);
    cur_cool_in_nvm = partial_cool(&nvm_hot_list, &nvm_cold_list, false, cur_cool_in_nvm);
    #else
    partial_cool(&dram_hot_list, &dram_cold_list, true);
    partial_cool(&nvm_hot_list, &nvm_cold_list, false);
    #endif
 
out:
#ifdef DYNA_THRESH
    gettimeofday(&start_histo, NULL);
    last_pages_read_cnt = update_thresholds();
    gettimeofday(&end_histo, NULL);       
    time_taken_histo = elapsed(&start_histo, &end_histo);
#endif
#ifdef SLOW_HISTO
    gettimeofday(&start_histo, NULL);
    last_pages_read_cnt = update_thresholds();
    gettimeofday(&end_histo, NULL);       
    time_taken_histo = elapsed(&start_histo, &end_histo);
#endif
    LOG_TIME("migrate: %f s\n", elapsed(&start, &end));
  }

  return NULL;
}
#endif


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
  #ifdef MULTI_LIST
    enqueue_fifo(&dram_lists[0], page);
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
#ifdef MULTI_LIST
    enqueue_fifo(&nvm_lists[0], page);
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
  uint64_t** buffer;

  LOG("pebs_init: started\n");

  for (int i = 0; i < PEBS_NPROCS; i++) {
    //perf_page[i][READ] = perf_setup(0x1cd, 0x4, i);  // MEM_TRANS_RETIRED.LOAD_LATENCY_GT_4
    //perf_page[i][READ] = perf_setup(0x81d0, 0, i);   // MEM_INST_RETIRED.ALL_LOADS
    perf_page[i][DRAMREAD] = perf_setup(0x1d3, 0, i, DRAMREAD);      // MEM_LOAD_L3_MISS_RETIRED.LOCAL_DRAM
    perf_page[i][NVMREAD] = perf_setup(0x80d1, 0, i, NVMREAD);     // MEM_LOAD_RETIRED.LOCAL_PMM
    //perf_page[i][WRITE] = perf_setup(0x82d0, 0, i, WRITE);    // MEM_INST_RETIRED.ALL_STORES
    //perf_page[i][WRITE] = perf_setup(0x12d0, 0, i);   // MEM_INST_RETIRED.STLB_MISS_STORES
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

  pthread_mutex_init(&(dram_hot_list.list_lock), NULL);
  pthread_mutex_init(&(dram_cold_list.list_lock), NULL);
  pthread_mutex_init(&(nvm_hot_list.list_lock), NULL);
  pthread_mutex_init(&(nvm_cold_list.list_lock), NULL);

  buffer = (uint64_t**)malloc(sizeof(uint64_t*) * CAPACITY);
  assert(buffer); 
  hot_ring = ring_buf_init(buffer, CAPACITY);
  buffer = (uint64_t**)malloc(sizeof(uint64_t*) * CAPACITY);
  assert(buffer); 
  cold_ring = ring_buf_init(buffer, CAPACITY);
  buffer = (uint64_t**)malloc(sizeof(uint64_t*) * CAPACITY);
  assert(buffer); 
  free_page_ring = ring_buf_init(buffer, CAPACITY);

  #ifdef MULTI_LIST
  buffer = (uint64_t**)malloc(sizeof(uint64_t*) * CAPACITY);
  assert(buffer); 
  make_hotter_ring = ring_buf_init(buffer, CAPACITY);

  buffer = (uint64_t**)malloc(sizeof(uint64_t*) * CAPACITY);
  assert(buffer); 
  make_colder_ring = ring_buf_init(buffer, CAPACITY);
  #endif

  int total_pages = dram_hot_list.numentries + dram_cold_list.numentries + dram_free_list.numentries +
                    nvm_hot_list.numentries + nvm_cold_list.numentries + nvm_free_list.numentries;
  reading_page_histogram[0] = total_pages;
  writing_page_histogram[0] = total_pages;
  
  int r = pthread_create(&scan_thread, NULL, pebs_scan_thread, NULL);
  assert(r == 0);
  
  r = pthread_create(&kswapd_thread, NULL, pebs_policy_thread, NULL);
  assert(r == 0);
  
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
  dump_samples();
}

void dump_samples() {
  FILE* f = fopen("./pebs_trace.txt", "w+");
  if(pebs_sample_buffer_idx >= PEBS_SAMPLE_B_SIZE) {
    fprintf(f, "Sample buffer overflowed\n");
  }
  uint64_t s = pebs_sample_buffer_idx > PEBS_SAMPLE_B_SIZE ? PEBS_SAMPLE_B_SIZE : pebs_sample_buffer_idx;
  fprintf(f, "num samples: %d\n", s);
  for(uint64_t i = 0; i < s; i++) {
    fprintf(f, "%ld %ld\n", pebs_samples[i], period_samples[i]);
  }
  fclose(f);
}

void log_multi_list()  {
  LOG_STATS("DRAM multi lists: [", NULL);
  for (int i = 0; i < NUM_HOTNESS_LEVELS; i++) {
    LOG_STATS("%ld, ", dram_lists[i].numentries);
  }
  LOG_STATS("]\n", NULL);

  LOG_STATS("NVM multi lists: [", NULL);
  for (int i = 0; i < NUM_HOTNESS_LEVELS; i++) {
    LOG_STATS("%ld, ", nvm_lists[i].numentries);
  }
  LOG_STATS("]\n", NULL);
}

void pebs_stats()
{
  LOG_STATS("dram_hot_list.numentries: [%ld]\tdram_cold_list.numentries: [%ld]\t"
            "nvm_hot_list.numentries: [%ld]\tnvm_cold_list.numentries: [%ld]\t"
            "fifo_list dram_free_list.numentries: [%ld]\tfifo_list nvm_free_list.numentries: [%ld]\t"
            "hemem_pages: [%lu]\ttotal_pages: [%lu]\tzero_pages: [%ld]\t"
            "throttle/unthrottle_cnt: [%ld/%ld]\tcools: [%ld]\tpages_read_cnt: [%ld]\t"
            "read_hot_thresh: [%ld]\twrite_hot_thresh: [%ld]\ttime_taken_histo: [%f]\t"
            "Lost samples: [%ld]\n",
	    dram_hot_list.numentries,
	    dram_cold_list.numentries,
	    nvm_hot_list.numentries,
	    nvm_cold_list.numentries,
	    dram_free_list.numentries,
	    nvm_free_list.numentries,
	    hemem_pages_cnt,
	    total_pages_cnt,
	    zero_pages_cnt,
	    throttle_cnt,
	    unthrottle_cnt,
	    cools,
	    last_pages_read_cnt,
	    reading_hot_thresh,
	    writing_hot_thresh,
	    time_taken_histo,
      lost_sample);
      LOG_STATS("Good/throttle samples: [%ld/%ld]\n", good_samples, throttle_cnt);

  log_histogram();
#ifdef MULTI_LIST
  log_multi_list();
#endif
  hemem_pages_cnt = total_pages_cnt = throttle_cnt = unthrottle_cnt = good_samples = 0;
}
