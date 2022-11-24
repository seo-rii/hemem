/*
 * =====================================================================================
 *
 *       Filename:  gups.c
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  02/21/2018 02:36:27 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <math.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>

#include "../src/ucm/timer.h"
//#include "../src/hemem.h"


#include "gups.h"

#define MAX_THREADS     64

#define GUPS_PAGE_SIZE      (4 * 1024)
#define PAGE_NUM            3
#define PAGES               2048

#ifdef HOTSPOT
extern uint64_t hotset_start;
extern double hotset_fraction;
#endif

#define IGNORE_STRAGGLERS

int threads;

uint64_t hot_start = 0;
uint64_t hotsize = 0;
bool move_hotset = false;

struct gups_args {
  int tid;                      // thread id
  uint64_t *indices;       // array of indices to access
  void* field;                  // pointer to start of thread's region
  uint64_t iters;          // iterations to perform
  uint64_t size;           // size of region
  uint64_t elt_size;       // size of elements
  uint64_t hot_start;            // start of hot set
  uint64_t hotsize;        // size of hot set
};


static inline uint64_t rdtscp(void)
{
    uint32_t eax, edx;
    // why is "ecx" in clobber list here, anyway? -SG&MH,2017-10-05
    __asm volatile ("rdtscp" : "=a" (eax), "=d" (edx) :: "ecx", "memory");
    return ((uint64_t)edx << 32) | eax;
}

uint64_t thread_gups[MAX_THREADS];

static unsigned long updates, nelems;

uint64_t tot_updates = 0;

static void *print_instantaneous_gups(void *arg)
{
  char *log_filename = (char *)(arg);
  FILE *tot;
  uint64_t tot_gups, tot_last_second_gups = 0;
  fprintf(stderr, "Opening instantaneous gups at %s\n", log_filename);
  tot = fopen(log_filename, "w");
  if (tot == NULL) {
    perror("fopen");
  }

  for (;;) {
    tot_gups = 0;
    for (int i = 0; i < threads; i++) {
      tot_gups += thread_gups[i];
    }
    fprintf(tot, "%.10f\n", (1.0 * (abs(tot_gups - tot_last_second_gups))) / (1.0e9));
    fflush(tot);
    tot_updates += abs(tot_gups - tot_last_second_gups);
    tot_last_second_gups = tot_gups;
    sleep(1);
  }

  return NULL;
}

static uint64_t lfsr_fast(uint64_t lfsr)
{
  lfsr ^= lfsr >> 7;
  lfsr ^= lfsr << 9;
  lfsr ^= lfsr >> 13;
  return lfsr;
}

char *filename = "indices1.txt";

FILE *hotsetfile = NULL;

bool hotset_only = false;

static void *prefill_hotset(void* arguments)
{
  struct gups_args *args = (struct gups_args*)arguments;
  uint64_t *field = (uint64_t*)(args->field);
  uint64_t i;
  uint64_t index1;

  index1 = 0;

  for (i = 0; i < args->hotsize; i++) {
    index1 = i;
    uint64_t  tmp = field[index1];
    tmp = tmp + i;
    field[index1] = tmp;
  }
  return 0;
  
}

bool done_gups = false;
unsigned completed_gups[MAX_THREADS] = {0};

static void *do_gups(void *arguments)
{
  //printf("do_gups entered\n");
  struct gups_args *args = (struct gups_args*)arguments;
  uint64_t *field = (uint64_t*)(args->field);
  uint64_t i;
  uint64_t index1, index2;
  uint64_t lfsr;
  uint64_t iters = args->iters;

  srand(args->tid);
  lfsr = rand();

  index1 = 0;
  index2 = 0;
  done_gups = false;
  completed_gups[args->tid] = 0;
 // fprintf(hotsetfile, "Thread %d region: %p - %p\thot set: %p - %p\n", args->tid, field, field + (args->size * elt_size), field + args->hot_start, field + args->hot_start + (args->hotsize * elt_size));   

  for (i = 0; i < iters || iters == 0; i++) {
    lfsr = lfsr_fast(lfsr);
    if (lfsr % 100 < 60) {
      lfsr = lfsr_fast(lfsr);
      index1 = args->hot_start + (lfsr % (args->hotsize)/2);
      uint64_t  tmp = field[index1];
      tmp = tmp + i;
      field[index1] = tmp;
    }
    else if (lfsr % 100 < 90) {
      lfsr = lfsr_fast(lfsr);
      index1 = args->hot_start + (args->hotsize/2) + (lfsr % (args->hotsize)/2);
      uint64_t  tmp = field[index1];
      tmp = tmp + i;
      field[index1] = tmp;
    }
    else {
      lfsr = lfsr_fast(lfsr);
      index2 = lfsr % (args->size);
      uint64_t tmp = field[index2];
      tmp = tmp + i;
      field[index2] = tmp;
    }
    if (i % 1000 == 0) {
      thread_gups[args->tid] += 1000;
    }
#ifdef IGNORE_STRAGGLERS
    if(done_gups)
      break;
#endif
  }
  done_gups = true;
  completed_gups[args->tid] = i;
  return 0;
}

bool received_signal = false;
void signal_handler() 
{
  received_signal = true;
}

int main(int argc, char **argv)
{
  unsigned long expt;
  unsigned long size, elt_size;
  unsigned long tot_hot_size;
  int log_hot_size;
  struct timeval starttime, stoptime;
  double secs, gups;
  int i;
  void *p;
  struct gups_args** ga;
  pthread_t t[MAX_THREADS];
  char *log_filename;
  bool wait_for_signal = false;

  // Stop waiting on receiving signal
  signal(SIGUSR1, signal_handler);

  if (argc < 6) {
    fprintf(stderr, "Usage: %s [threads] [updates per thread] [exponent] [data size (bytes)] [noremap/remap] [wait] [instantaneous_filename]\n", argv[0]);
    fprintf(stderr, "  threads\t\t\tnumber of threads to launch\n");
    fprintf(stderr, "  updates per thread\t\tnumber of updates per thread (0 = unlimited)\n");
    fprintf(stderr, "  exponent\t\t\tlog size of region\n");
    fprintf(stderr, "  data size\t\t\tsize of data in array (in bytes)\n");
    fprintf(stderr, "  hot size\t\t\tlog size of hot set\n");
    fprintf(stderr, "  wait\t\t\twait for signal to start GUPS [1=true, default 0]\n");
    fprintf(stderr, "  log filename\t\t\tthe filename of instantaneous gups.\n");
    return 0;
  }

  gettimeofday(&starttime, NULL);

  threads = atoi(argv[1]);
  assert(threads <= MAX_THREADS);
  ga = (struct gups_args**)malloc(threads * sizeof(struct gups_args*));

  updates = atol(argv[2]);
  updates -= updates % 256;
  expt = atoi(argv[3]);
  assert(expt > 8);
  assert((updates % 256 == 0));
  size = (unsigned long)(1) << expt;
  size -= (size % 256);
  assert(size > 0 && (size % 256 == 0));
  elt_size = atoi(argv[4]);
  log_hot_size = atof(argv[5]);
  tot_hot_size = (unsigned long)(1) << log_hot_size;

  if(argc > 6 && atoi(argv[6]))
    wait_for_signal = true;
  log_filename = argv[7];

  fprintf(stderr, "%lu updates per thread (%d threads)\n", updates, threads);
  fprintf(stderr, "field of 2^%lu (%lu) bytes\n", expt, size);
  fprintf(stderr, "%ld byte element size (%ld elements total)\n", elt_size, size / elt_size);

  p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE, -1, 0);
  if (p == MAP_FAILED) {
    perror("mmap");
    assert(0);
  }

  gettimeofday(&stoptime, NULL);
  fprintf(stderr, "Init took %.4f seconds\n", elapsed(&starttime, &stoptime));
  fprintf(stderr, "Region address: %p - %p\t size: %ld\n", p, (p + size), size);
  
  nelems = (size / threads) / elt_size; // number of elements per thread
  fprintf(stderr, "Elements per thread: %lu\n", nelems);

  //memset(thread_gups, 0, sizeof(thread_gups));

  hotsetfile = fopen("hotsets.txt", "w");
  if (hotsetfile == NULL) {
    perror("fopen");
    assert(0);
  }

  gettimeofday(&stoptime, NULL);
  secs = elapsed(&starttime, &stoptime);
  fprintf(stderr, "Initialization time: %.4f seconds.\n", secs);

  //hemem_start_timing();

  //pthread_t print_thread;
  //int pt = pthread_create(&print_thread, NULL, print_instantaneous_gups, NULL);
  //assert(pt == 0);


  hot_start = 0;
  hotsize = (tot_hot_size / threads) / elt_size;
  //printf("hot_start: %p\thot_end: %p\thot_size: %lu\n", p + hot_start, p + hot_start + (hotsize * elt_size), hotsize);

  gettimeofday(&starttime, NULL);
  for (i = 0; i < threads; i++) {
    //printf("starting thread [%d]\n", i);
    ga[i] = (struct gups_args*)malloc(sizeof(struct gups_args));
    ga[i]->tid = i;
    ga[i]->field = p + (i * nelems * elt_size);
    ga[i]->iters = updates;
    ga[i]->size = nelems;
    ga[i]->elt_size = elt_size;
    ga[i]->hot_start = 0;        // hot set at start of thread's region
    ga[i]->hotsize = hotsize;
  }

  if (hotset_only) {
    for (i = 0; i < threads; i++) {
      int r = pthread_create(&t[i], NULL, prefill_hotset, (void*)ga[i]);
      assert(r == 0);
    }
    // wait for worker threads
    for (i = 0; i < threads; i++) {
      int r = pthread_join(t[i], NULL);
      assert(r == 0);
    }
  }

  if(updates != 0) {
    // run through gups once to touch all memory
    // spawn gups worker threads
    for (i = 0; i < threads; i++) {
      int r = pthread_create(&t[i], NULL, do_gups, (void*)ga[i]);
      assert(r == 0);
    }

    // wait for worker threads
    for (i = 0; i < threads; i++) {
      int r = pthread_join(t[i], NULL);
      assert(r == 0);
    }
    //hemem_print_stats();

    gettimeofday(&stoptime, NULL);

    secs = elapsed(&starttime, &stoptime);
    printf("Elapsed time: %.4f seconds.\n", secs);
    gups = 0;
    for(int i = 0; i < threads; ++i)
      gups += completed_gups[i];
    gups /= (secs * 1.0e9);
    printf("GUPS = %.10f\n", gups);
  }
  filename = "indices2.txt";

  memset(thread_gups, 0, sizeof(thread_gups));
  if(wait_for_signal) {
    fprintf(stderr, "Waiting for signal\n");
    while(!received_signal);
    fprintf(stderr, "Received signal\n");
  }
  pthread_t print_thread;
  int pt = pthread_create(&print_thread, NULL, print_instantaneous_gups, log_filename);
  assert(pt == 0);

  fprintf(stderr, "Timing.\n");
  gettimeofday(&starttime, NULL);

  //hemem_clear_stats();
  // spawn gups worker threads
  for (i = 0; i < threads; i++) {
    int r = pthread_create(&t[i], NULL, do_gups, (void*)ga[i]);
    assert(r == 0);
  }

  // wait for worker threads
  for (i = 0; i < threads; i++) {
    int r = pthread_join(t[i], NULL);
    assert(r == 0);
  }
  gettimeofday(&stoptime, NULL);
  //hemem_print_stats();
  //hemem_clear_stats();

  secs = elapsed(&starttime, &stoptime);
  printf("Elapsed time: %.4f seconds.\n", secs);
  gups = 0;
  for(int i = 0; i < threads; ++i)
    gups += completed_gups[i];
  gups /= (secs * 1.0e9);
  printf("GUPS = %.10f\n", gups);

  //memset(thread_gups, 0, sizeof(thread_gups));

#if 0
  FILE* pebsfile = fopen("pebs.txt", "w+");
  assert(pebsfile != NULL);
  for (uint64_t addr = (uint64_t)p; addr < (uint64_t)p + size; addr += (2*1024*1024)) {
    struct hemem_page *pg = get_hemem_page(addr);
    assert(pg != NULL);
    if (pg != NULL) {
      fprintf(pebsfile, "0x%lx:\t%lu\t%lu\t%lu\n", pg->va, pg->tot_accesses[DRAMREAD], pg->tot_accesses[NVMREAD], pg->tot_accesses[WRITE]);
    }
  }
#endif
  //hemem_stop_timing();

  for (i = 0; i < threads; i++) {
    //free(ga[i]->indices);
    free(ga[i]);
  }
  free(ga);

  //getchar();

  munmap(p, size);

  return 0;
}


