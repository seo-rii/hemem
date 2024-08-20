#ifndef HEMEM_PEBS_H
#define HEMEM_PEBS_H

#include <pthread.h>
#include <stdint.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include "hemem.h"

#define PEBS_KSWAPD_INTERVAL      (10000) // in us (10ms)
#define PEBS_KSWAPD_MIGRATE_RATE  (10UL * 1024UL * 1024UL * 1024UL) // 10GB
#define HOT_READ_THRESHOLD        (8)
#define HOT_WRITE_THRESHOLD       (4)
#define PEBS_COOLING_THRESHOLD    (18)
// #define PEBS_COOLING_THRESHOLD    (1000)
#define MAX_HISTOGRAM_BINS        (20) // when HISTOGRAM is enabled

#define HOT_RING_REQS_THRESHOLD   (1024*1024)
#define COLD_RING_REQS_THRESHOLD  (128)
#define CAPACITY                  (128*1024*1024)
#define COOLING_PAGES             (8192)

#define PEBS_NPROCS 32
#define PERF_PAGES	(1 + (1 << 16))	// Has to be == 1+2^n, here 1MB
// #define SAMPLE_PERIOD	101
#define SAMPLE_PERIOD 5003
//#define SAMPLE_FREQ	100


#define EWMA_FRAC (0.5)

#define SCANNING_THREAD_CPU_DEFAULT (63)
#define MIGRATION_THREAD_CPU_DEFAULT (61)

extern uint64_t hemem_cpu_start;
extern uint64_t scanning_thread_cpu;
extern uint64_t migration_thread_cpu;

#define COOL_IN_PLACE
#define COLLOID
// #define HISTOGRAM // Make sure COOL_IN_PLACE is also set
#define COLLOID_BETA (1.5) // colloid \beta parameter
// #define DUMP_FREQ // Scan and dump page access frequencies on exit
#define SCAN_AND_SORT // PFA implementation using scan and sort
#define COLLOID_EWMA (0.0625)
//#define COLLOID_EXPR1
#define COLLOID_EXPR3
//#define COLLOID_BINSEARCH
#define COLLOID_DELTA 0.05
#define COLLOID_EPSILON 0.01
// #define SAMPLE_BASED_COOLING
#define SAMPLE_COOLING_THRESHOLD 1000
#define COLLOID_DYNAMIC_LIMIT
#define COLLOID_COOLING
#define RATE_BETA

struct perf_sample {
  struct perf_event_header header;
  __u64	ip;
  __u32 pid, tid;    /* if PERF_SAMPLE_TID */
  __u64 addr;        /* if PERF_SAMPLE_ADDR */
  __u64 weight;      /* if PERF_SAMPLE_WEIGHT */
  /* __u64 data_src;    /\* if PERF_SAMPLE_DATA_SRC *\/ */
};

enum pbuftype {
  DRAMREAD = 0,
  NVMREAD = 1,  
//  WRITE = 2,
  NPBUFTYPES
};

void *pebs_kswapd();
struct hemem_page* pebs_pagefault(void);
struct hemem_page* pebs_pagefault_unlocked(void);
void pebs_init(void);
void pebs_remove_page(struct hemem_page *page);
void pebs_stats();
void pebs_shutdown();

#endif /*  HEMEM_LRU_MODIFIED_H  */
