#ifndef HEMEM_TYPES_H
#define HEMEM_TYPES_H

#define HEMEM_GLOBAL

enum pbuftype {
    DRAMREAD = 0,
    NVMREAD = 1,
//    WRITE = 2,
    NPBUFTYPES
};

enum HOTNESS {
  COLD,
  HOT1,
  HOT2,
  HOT3,
  HOT4,
  HOT5,
  HOT6,
  NUM_HOTNESS_LEVELS
};

struct hemem_page_key {
  uint64_t va;
  pid_t pid;
};

struct hemem_page {
  uint64_t va;
  pid_t pid;
  uint64_t devdax_offset;
  bool in_dram;
  long  uffd;
  int remap_fd;
  enum pagetypes pt;
  volatile bool migrating;
  bool in_migrate_up_queue;
  bool in_migrate_down_queue;
  bool present;
  uint64_t hot;
  uint64_t naccesses;
  uint64_t migrations_up, migrations_down;
  uint64_t local_clock;
  bool ring_present;
  uint64_t accesses[NPBUFTYPES];
  uint64_t tot_accesses[NPBUFTYPES];

  UT_hash_handle hh;
  struct hemem_page *next, *prev;
  struct page_list *list;
};

struct hemem_process {
  pid_t pid;
  long uffd;
  _Atomic bool exited;
  bool valid_uffd;
  _Atomic bool pending_remap;
  int remap_fd;
#ifdef HEMEM_GLOBAL
   FILE* logfd;
#endif

  _Atomic uint64_t volatile current_dram;
  _Atomic uint64_t volatile current_nvm;

  struct hemem_page* pages;
  pthread_mutex_t pages_lock;
  UT_hash_handle phh;

  struct hemem_process *next, *prev;
  struct process_list *list;

  pthread_mutex_t process_lock;
};

#endif
