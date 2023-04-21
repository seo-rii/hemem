#ifndef HEMEM_UCM_H
#define HEMEM_UCM_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/epoll.h>
#include <sys/time.h>

#include "uthash.h"
#include "spsc-ring.h"
#include "fifo.h"
#include "hemem-shared.h"
#include "hemem-types.h"

#define MAX_UFFD_MSGS	    (3)

//#define USE_DMA
#define USE_PARALLEL_MEMCPY

#ifdef USE_DMA
  #define NUM_CHANNS 1
  #define SIZE_PER_DMA_REQUEST (1024*1024)
#else
  #ifdef USE_PARALLEL_MEMCPY
    #define MAX_COPY_THREADS 4
  #endif
#endif

#define MAX_EVENTS 128

#define MAX_PROCESSES 24

#define FAULT_THREAD_CPU  (0)
#define LISTEN_THREAD_CPU (FAULT_THREAD_CPU)
#define REQUEST_THREAD_CPU (FAULT_THREAD_CPU + 1)
#define SCANNING_THREAD_CPU (REQUEST_THREAD_CPU + 1)
#define POLICY_THREAD_CPU (SCANNING_THREAD_CPU + 1)
//#define MIGRATION_THREAD_CPU (POLICY_THREAD_CPU + 1)

#ifdef USE_DMA
  #define LAST_HEMEM_THREAD (POLICY_THREAD_CPU)
#else
  #ifdef USE_PARALLEL_MEMCPY
    #define PARALLEL_MIGRATE_THREAD_CPU (POLICY_THREAD_CPU + 1)
    #define LAST_HEMEM_THREAD (POLICY_THREAD_CPU + MAX_COPY_THREADS)
  #else
    #define LAST_HEMEM_THREAD (POLICY_THREAD_CPU)
  #endif
#endif


extern int dramfd;
extern int nvmfd;
extern struct timeval startup;

extern struct page_list dram_lists[NUM_HOTNESS_LEVELS + 1];
extern struct page_list nvm_lists[NUM_HOTNESS_LEVELS + 1];
extern int cur_cool_in_dram_list;
extern int cur_cool_in_nvm_list;
extern struct hemem_page *cur_cool_in_dram;
extern struct hemem_page *cur_cool_in_nvm;
extern volatile bool need_cool_dram;
extern volatile bool need_cool_nvm;
extern volatile ring_handle_t hot_ring;
extern volatile ring_handle_t cold_ring;
extern volatile ring_handle_t free_page_ring;
extern pthread_mutex_t free_page_ring_lock;

void hemem_ucm_init();
void hemem_ucm_stop();
void *handle_fault();
void *handle_request();
void *accept_new_app();
void hemem_ucm_migrate_up(struct hemem_page *page, uint64_t dram_offset);
void hemem_ucm_migrate_down(struct hemem_page *page, uint64_t nvm_offset);
void hemem_ucm_wp_page(struct hemem_page *page, bool protect);
//void hemem_ucm_promote_pages(uint64_t addr);
//void hemem_ucm_demote_pages(uint64_t addr);
void add_process(struct hemem_process *process);
void remove_process(struct hemem_process *process);
struct hemem_process *find_process(pid_t pid);
void add_page(struct hemem_page *page);
void remove_page(struct hemem_page *page);
struct hemem_page *find_page(uint64_t app_va, pid_t pid);

// from the ucm to the app
int remap_pages(pid_t pid, int remap_fd, struct hemem_page_app* fault_pages, int num_fault_pages);

void hemem_print_stats();
void hemem_clear_stats();

void hemem_start_timing(void);
void hemem_stop_timing(void);

bool can_migrate_page(pid_t pid);

extern struct hemem_process *processes;
extern pthread_mutex_t processes_lock;
#endif /* HEMEM_UCM_H */
