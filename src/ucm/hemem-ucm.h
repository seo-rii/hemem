#ifndef HEMEM_UCM_H
#define HEMEM_UCM_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/epoll.h>
#include "uthash.h"
#include "spsc-ring.h"
#include "fifo.h"
#include "pebs.h"
#include "hemem-shared.h"

#define MAX_UFFD_MSGS	    (3)

#define USE_DMA
#define NUM_CHANNS 1
#define SIZE_PER_DMA_REQUEST (1024*1024)
#define MAX_COPY_THREADS 4

#define MAX_EVENTS 128

struct hemem_page {
  uint64_t va;
  uint64_t devdax_offset;
  pid_t pid;
  long  uffd;
  bool in_dram;
  enum pagetypes pt;
  volatile bool migrating;
  bool present;
  bool written;
  bool hot;
  uint64_t naccesses;
  uint64_t migrations_up, migrations_down;
  uint64_t local_clock;
  bool ring_present;
  uint64_t accesses[NPBUFTYPES];
  uint64_t tot_accesses[NPBUFTYPES];
  pthread_mutex_t page_lock;

  UT_hash_handle hh;
  struct hemem_page *next, *prev;
  struct fifo_list *list;
};

struct hemem_process {
  pid_t pid;
  long uffd;
  bool valid_uffd;
  int remap_fd;
  struct fifo_list dram_hot_list;
  struct fifo_list dram_cold_list;
  struct fifo_list nvm_hot_list;
  struct fifo_list nvm_cold_list;
  struct hemem_page* cur_cool_in_dram;
  struct hemem_page* cur_cool_in_nvm;
  volatile ring_handle_t hot_ring;
  volatile ring_handle_t cold_ring;
  volatile ring_handle_t free_page_ring;
  pthread_mutex_t free_page_ring_lock;
  struct hemem_page* start_dram_page;
  struct hemem_page* start_nvm_page;
  struct hemem_page* pages;
  volatile bool need_cool_dram;
  volatile bool need_cool_nvm;
  pthread_mutex_t pages_lock;
  UT_hash_handle hh;
};

extern int dramfd;
extern int nvmfd;
extern int devmemfd;
extern pthread_t fault_thread;
extern pthread_t request_thread;

#define pagefault(...) pebs_pagefault(__VA_ARGS__)
#define page_free(...) pebs_remove_page(__VA_ARGS__)
#define paging_init(...) pebs_init(__VA_ARGS__)
#define mmgr_remove(...) pebs_remove_page(__VA_ARGS__)
#define mmgr_stats(...) pebs_stats(__VA_ARGS__)
#define policy_shutdown(...) pebs_shutdown(__VA_ARGS__)

void hemem_ucm_init();
void hemem_ucm_stop();
void *handle_fault();
void *handle_request();
void *accept_new_app();
void hemem_ucm_migrate_up(struct hemem_process *process, struct hemem_page *page, uint64_t dram_offset);
void hemem_ucm_migrate_down(struct hemem_process *process, struct hemem_page *page, uint64_t nvm_offset);
void hemem_ucm_wp_page(struct hemem_page *page, bool protect);
void hemem_ucm_promote_pages(uint64_t addr);
void hemem_ucm_demote_pages(uint64_t addr);
void add_process(struct hemem_process *process);
void remove_process(struct hemem_process *process);
struct hemem_process *find_process(pid_t pid);
void add_page(struct hemem_process* process, struct hemem_page *page);
void remove_page(struct hemem_process* process, struct hemem_page *page);
struct hemem_page *find_page(struct hemem_process* process, uint64_t app_va);

// from the ucm to the app
int remap_pages(pid_t pid, int remap_fd, struct hemem_page_app* fault_pages, int num_fault_pages);

void hemem_print_stats();
void hemem_clear_stats();

void hemem_start_timing(void);
void hemem_stop_timing(void);

extern struct hemem_process *processes;

#endif /* HEMEM_UCM_H */
