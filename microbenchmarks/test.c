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
#include <sched.h>

#include "../src/ucm/timer.h"
//#include "../src/hemem.h"


#include "gups.h"

#define MAX_THREADS     24

int threads;

uint64_t thread_gups[MAX_THREADS];
uint64_t tot_updates;
void *region_dram, *region_nvm;
uint64_t dram_size, nvm_size;

int start_cpu = 8;

volatile char *current_region;
volatile uint64_t current_size;

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

void signal_handler() 
{
  if(current_region == region_nvm) {
    current_region = (char*)region_dram;
    current_size = dram_size;
  } else {
    current_region = (char*)region_nvm;
    current_size = nvm_size;
  }
}

static uint64_t lfsr_fast(uint64_t lfsr)
{
  lfsr ^= lfsr >> 7;
  lfsr ^= lfsr << 9;
  lfsr ^= lfsr >> 13;
  return lfsr;
}

static void *do_gups(void *tid)
{
  //printf("do_gups entered\n");
  uint64_t i;
  uint64_t index;
  uint64_t lfsr;

  cpu_set_t cpuset;
  pthread_t thread;

  thread = pthread_self();
  CPU_ZERO(&cpuset);
  CPU_SET(start_cpu + (uint64_t)tid, &cpuset);
  int s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (s != 0) {
    perror("pthread_setaffinity_np");
    assert(0);
  }

  srand((uint64_t)tid);
  lfsr = rand();

  index = 0;
  i = 0;

  while (1) {
    lfsr = lfsr_fast(lfsr);
    index = lfsr % current_size;
    uint64_t tmp = current_region[index];
    tmp = tmp + i;
    current_region[index] = tmp;
    if (i % 1000 == 0) {
      thread_gups[(uint64_t)tid] += 1000;
    }
    i++;
  }
  
  return 0;
}

int main(int argc, char **argv)
{
  unsigned long dram_expt, nvm_expt;
  struct timeval starttime, stoptime;
  uint64_t i;
  pthread_t t[MAX_THREADS];
  char *log_filename;
  char *start_cpu_str;

  // Stop waiting on receiving signal
  signal(SIGUSR1, signal_handler);

  if (argc < 5) {
    fprintf(stderr, "Usage: %s [threads] [dram_exponent] [nvm_exponent] [instantaneous_filename]\n", argv[0]);
    fprintf(stderr, "  threads\t\t\tnumber of threads to launch\n");
    fprintf(stderr, "  dram exponent\t\t\tlog size of dram region\n");
    fprintf(stderr, "  nvm exponent\t\t\tlog size of nvm region\n");
    fprintf(stderr, "  log filename\t\t\tthe filename of instantaneous gups.\n");
    return 0;
  }

  gettimeofday(&starttime, NULL);

  threads = atoi(argv[1]);
  assert(threads <= MAX_THREADS);

  dram_expt = atoi(argv[2]);
  assert(dram_expt > 8);
  dram_size = (unsigned long)(1) << dram_expt;
  dram_size -= (dram_size % 256);
  assert(dram_size > 0 && (dram_size % 256 == 0));
  
  nvm_expt = atoi(argv[3]);
  assert(nvm_expt > 8);
  nvm_size = (unsigned long)(1) << nvm_expt;
  nvm_size -= (nvm_size % 256);
  assert(nvm_size > 0 && (nvm_size % 256 == 0));
  
  log_filename = argv[4];

  fprintf(stderr, "dram region size of 2^%lu (%lu) bytes\n", dram_expt, dram_size);
  fprintf(stderr, "nvm region size of 2^%lu (%lu) bytes\n", nvm_expt, nvm_size);

  start_cpu_str = getenv("START_CPU");
  if (start_cpu_str != NULL) {
    start_cpu = atoi(start_cpu_str);
  }

  region_dram = mmap(NULL, dram_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE, -1, 0);
  if (region_dram == MAP_FAILED) {
    perror("mmap");
    assert(0);
  }
  
  region_nvm = mmap(NULL, nvm_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE, -1, 0);
  if (region_nvm == MAP_FAILED) {
    perror("mmap");
    assert(0);
  }

  current_region = region_nvm;
  current_size = dram_size; // XXX: Should this be nvm_size?
  
  gettimeofday(&stoptime, NULL);
  fprintf(stderr, "Init took %.4f seconds\n", elapsed(&starttime, &stoptime));
  fprintf(stderr, "DRAM region address: %p - %p\t size: %ld\n", region_dram, (region_dram + dram_size), dram_size);
  fprintf(stderr, "NVM region address: %p - %p\t size: %ld\n", region_nvm, (region_nvm + nvm_size), nvm_size);
  
  pthread_t print_thread;
  int pt = pthread_create(&print_thread, NULL, print_instantaneous_gups, log_filename);
  assert(pt == 0);

  fprintf(stderr, "Timing.\n");
  gettimeofday(&starttime, NULL);

  //hemem_clear_stats();
  // spawn gups worker threads
  for (i = 0; i < threads; i++) {
    int r = pthread_create(&t[i], NULL, do_gups, (void*)i);
    assert(r == 0);
  }

  // wait for worker threads
  for (i = 0; i < threads; i++) {
    int r = pthread_join(t[i], NULL);
    assert(r == 0);
  }
  gettimeofday(&stoptime, NULL);

  munmap(region_dram, dram_size);
  munmap(region_nvm, nvm_size);

  return 0;
}


