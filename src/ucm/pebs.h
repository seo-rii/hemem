#ifndef HEMEM_PEBS_H
#define HEMEM_PEBS_H

#include <pthread.h>
#include <stdint.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include "hemem-types.h"

#define PEBS_KSWAPD_INTERVAL      (10000) // in us (10ms)
#define PEBS_KSWAPD_MIGRATE_RATE  (10UL * 1024UL * 1024UL * 1024UL) // 10GB
#define PEBS_MIGRATE_DOWN_RATE    (1UL * 1024UL * 1024UL * 1024UL) // 1GB
#define PEBS_MIGRATE_UP_RATE      (1UL * 1024UL * 1024UL * 1024UL) // 1GB
#define PEBS_MIGRATE_MAX_UP_RATE      (10UL * 1024UL * 1024UL * 1024UL) // 10GB
#define HOT_READ_THRESHOLD        (2)
//#define HOT_WRITE_THRESHOLD       (4)
#define PEBS_COOLING_THRESHOLD    (22)

#define HOT_RING_REQS_THRESHOLD   (1024*1024)
#define COLD_RING_REQS_THRESHOLD  (128)
#define COOLING_PAGES             (8192)

#define PEBS_NPROCS 24
#define PERF_PAGES	(1 + (1 << 8))	// Has to be == 1+2^n, here 1MB
//#define SAMPLE_PERIOD	10007
#define SAMPLE_PERIOD 5003
//#define SAMPLE_FREQ	100


//#define HEMEM_QOS


#define MISS_RATIO_TOLERANCE (0.1)

extern struct hemem_process *process_list[NPRIORITYTYPES];

struct perf_sample {
    struct perf_event_header header;
    __u64	ip;
    __u32 pid, tid;    /* if PERF_SAMPLE_TID */
    __u64 addr;        /* if PERF_SAMPLE_ADDR */
    __u64 weight;      /* if PERF_SAMPLE_WEIGHT */
};

void pebs_remove_page(struct hemem_process *process, struct hemem_page *page);
struct hemem_page* pebs_pagefault(struct hemem_process *process);
void pebs_init(void);
void pebs_stats();
void pebs_shutdown();
void pebs_add_process(struct hemem_process *process); 
void pebs_remove_process(struct hemem_process *process);

#endif /*  HEMEM_PEBS_H  */
