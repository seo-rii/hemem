#ifndef HEMEM_TYPES_H
#define HEMEM_TYPES_H

enum pbuftype {
    DRAMREAD = 0,
    NVMREAD = 1,
//    WRITE = 2,
    NPBUFTYPES
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
  int priority;
  double expect_miss_ratio;
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
  uint64_t access_pages_in_dram;
  uint64_t access_pages_in_nvm;
  UT_hash_handle phh;
};

#endif
