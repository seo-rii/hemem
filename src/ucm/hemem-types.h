#ifndef HEMEM_TYPES_H
#define HEMEM_TYPES_H

enum pbuftype {
    DRAMREAD = 0,
    NVMREAD = 1,
//    WRITE = 2,
    NPBUFTYPES
};

enum prioritytype {
  BESTEFFORT = 0,
  LATENCYCRITICAL = 1,
  NPRIORITYTYPES
};

struct hemem_page {
  uint64_t va;
  uint64_t devdax_offset;
  pid_t pid;
  long  uffd;
  bool in_dram;
  enum pagetypes pt;
  volatile bool migrating;
  bool present;
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
  struct page_list *list;
};

struct hemem_process {
  pid_t pid;
  long uffd;
  enum prioritytype priority;
  double target_miss_ratio;
  uint64_t migrate_up_bytes;
  uint64_t migrate_down_bytes;
  bool valid_uffd;
  int remap_fd;
  struct page_list dram_hot_list;
  struct page_list dram_cold_list;
  struct page_list nvm_hot_list;
  struct page_list nvm_cold_list;
  struct hemem_page* cur_cool_in_dram;
  struct hemem_page* cur_cool_in_nvm;
  volatile bool need_cool;
  volatile ring_handle_t hot_ring;
  volatile ring_handle_t cold_ring;
  volatile ring_handle_t free_page_ring;
  pthread_mutex_t free_page_ring_lock;
  struct hemem_page* pages;
  pthread_mutex_t pages_lock;
  uint64_t accessed_pages[NPBUFTYPES];
  UT_hash_handle phh;
  struct hemem_process *next, *prev;
  struct process_list *list;
};

#endif
