#ifndef HEMEM_APP_H

#define HEMEM_APP_H

#include <pthread.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>

#ifndef __cplusplus
#include <stdatomic.h>
#else
#include <atomic>
#define _Atomic(X) std::atomic< X >
#endif

#ifdef __cplusplus
extern "C" {
#endif


#include "interpose.h"
#include "hemem-shared.h"
#include "logging.h"

#define MAX_UFFD_MSGS	    (1)

extern int dramfd;
extern int nvmfd;
extern int devmemfd;
extern pid_t pid;
extern long uffd;
extern uint64_t msg_id;
extern bool is_init;
extern __thread bool internal_call;
extern pthread_mutex_t channel_lock;

void hemem_app_init();
void hemem_app_stop();
void* hemem_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int hemem_munmap(void* addr, size_t length);

void* process_request(int fd, void* request);

// from the app to the ucm
struct alloc_response* alloc_space(void *addr, size_t length);
int free_space(void *addr, size_t length);
int add_process();
int remove_process();
int get_uffd(long uffd);
int record_remap_channel();

#ifdef __cplusplus
}
#endif

#endif /* HEMEM_APP_H */
