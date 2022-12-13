
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/userfaultfd.h>
#include <math.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/epoll.h>

#define NUM_CHANNS 2
#define SIZE_PER_DMA_REQUEST (2*1024*1024/NUM_CHANNS)

#define DRAMPATH  "/dev/dax0.0"
#define NVMPATH   "/dev/dax1.0"

#define NVMSIZE   (8L * (1024L * 1024L * 1024L))
#define DRAMSIZE  (4L * (1024L * 1024L * 1024L))
#define PAGESIZE (2 * 1024 * 1024)

int dramfd = -1;
int nvmfd = -1;
int uffd = -1;
void *dram_devdax_mmap;
void *nvm_devdax_mmap;

void dma(int *old_addr, int *new_addr) 
{
  struct uffdio_dma_copy uffdio_dma_copy;

  uffdio_dma_copy.src[0] = (uint64_t)old_addr & (~(PAGESIZE - 1));
  uffdio_dma_copy.dst[0] = (uint64_t)new_addr & (~(PAGESIZE - 1));
  uffdio_dma_copy.len[0] = 2 * 1024 * 1024;
  uffdio_dma_copy.count = 1;
  uffdio_dma_copy.mode = 0;
  uffdio_dma_copy.copy = 0;
  if (ioctl(uffd, UFFDIO_DMA_COPY, &uffdio_dma_copy) == -1) {
    assert(false);
  }
}

int main()
{
  struct uffdio_api uffdio_api;
  struct uffdio_dma_channs uffdio_dma_channs;
/*
  dramfd = open(DRAMPATH, O_RDWR);
  if (dramfd < 0) {
    perror("dram open");
  }
  assert(dramfd >= 0);

  nvmfd = open(NVMPATH, O_RDWR);
  if (nvmfd < 0) {
    perror("nvm open");
  }
  assert(nvmfd >= 0);
*/

  dram_devdax_mmap = mmap(NULL, DRAMSIZE, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_POPULATE | MAP_ANONYMOUS, -1, 0);
  if (dram_devdax_mmap == MAP_FAILED) {
    perror("dram devdax mmap");
    assert(0);
  }

  nvm_devdax_mmap = mmap(NULL, NVMSIZE, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_POPULATE | MAP_ANONYMOUS, -1, 0);
  if (nvm_devdax_mmap == MAP_FAILED) {
    perror("nvm devdax mmap");
    assert(0);
  }

  uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if (uffd == -1) {
    perror("uffd");
    assert(0);
  }

  uffdio_api.api = UFFD_API;
  uffdio_api.features =
      UFFD_FEATURE_PAGEFAULT_FLAG_WP | UFFD_FEATURE_MISSING_SHMEM |
      UFFD_FEATURE_MISSING_HUGETLBFS; 
  uffdio_api.ioctls = 0;
  if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1) {
    perror("ioctl uffdio_api");
    assert(0);
  }


  uffdio_dma_channs.num_channs = NUM_CHANNS;
  uffdio_dma_channs.size_per_dma_request = SIZE_PER_DMA_REQUEST;
  if (ioctl(uffd, UFFDIO_DMA_REQUEST_CHANNS, &uffdio_dma_channs) == -1) {
    perror("ioctl UFFDIO_API\n");
    assert(0);
  }

  memset(dram_devdax_mmap, 0, DRAMSIZE);
  memset(nvm_devdax_mmap, 0, NVMSIZE);

  memset(dram_devdax_mmap, 1, 2*1024*1024);

  fprintf(stderr, "Finished init\n");
  fprintf(stderr, "%d\n", *(int*)nvm_devdax_mmap);
  for(int i = 0; i < 10000; ++i) {
    dma((int *)dram_devdax_mmap + i % (DRAMSIZE / 4), (int*)nvm_devdax_mmap + i % (NVMSIZE / 4));
  }

  printf("0x%x\n", *(int*)nvm_devdax_mmap);
  munmap(nvm_devdax_mmap, NVMSIZE);
  munmap(dram_devdax_mmap, DRAMSIZE);
}