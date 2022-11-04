#ifndef HEMEM_UCM_H
#define HEMEM_UCM_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/epoll.h>

#include "uthash.h"
#include "spsc-ring.h"
#include "fifo.h"
#include "hemem-shared.h"
#include "hemem-types.h"

#define MAX_UFFD_MSGS	    (3)

#define USE_DMA
#define NUM_CHANNS 2
#define SIZE_PER_DMA_REQUEST (1024*1024)
#define MAX_COPY_THREADS 4

#define MAX_EVENTS 128

#define MAX_PROCESSES 24

extern int dramfd;
extern int nvmfd;

void hemem_ucm_init();
void hemem_ucm_stop();
void *handle_fault();
void *handle_request();
void *accept_new_app();
void hemem_ucm_migrate_up(struct hemem_process *process, struct hemem_page *page, uint64_t dram_offset);
void hemem_ucm_migrate_down(struct hemem_process *process, struct hemem_page *page, uint64_t nvm_offset);
void hemem_ucm_wp_page(struct hemem_page *page, bool protect);
//void hemem_ucm_promote_pages(uint64_t addr);
//void hemem_ucm_demote_pages(uint64_t addr);
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

extern volatile struct hemem_process *processes;
extern pthread_mutex_t processes_lock;
#endif /* HEMEM_UCM_H */
