#include <inttypes.h>
#include <sys/types.h>
#include <stdio.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "shared.h"

int main(int argc, char *argv[])
{
    char *mmap_addr;         /* Start of region handled by userfaultfd */
    uint64_t len;       /* Length of region handled by userfaultfd */
    pthread_t thr;      /* ID of thread that handles page faults */
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;
    int page_size;
    long uffd;
    int ret;

    if (argc != 2) {
       fprintf(stderr, "Usage: %s num-pages\n", argv[0]);
       exit(EXIT_FAILURE);
    }

    page_size = sysconf(_SC_PAGE_SIZE);
    len = strtoull(argv[1], NULL, 0) * page_size;

    /* Create and enable userfaultfd object */

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
       errExit("userfaultfd");

    printf("uffd on the user application:%ld\n", uffd);

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
       errExit("ioctl-UFFDIO_API");

    /* unix socket client */
    struct sockaddr_un addr;
    struct sockaddr_un from;
    int fd;
    fd = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        errExit("socket");
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, CLIENT_SOCK_FILE);
    unlink(CLIENT_SOCK_FILE);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        errExit("bind");
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SERVER_SOCK_FILE);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        errExit("connect");
    }

    // send uffd
    ret = send_fd(fd, NULL, 0, uffd);
    if (ret) {
        errExit("send");
    }

    /* Create a private anonymous mapping. The memory will be
      demand-zero paged--that is, not yet allocated. When we
      actually touch the memory, it will be allocated via
      the userfaultfd. */

    mmap_addr = mmap(NULL, len, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mmap_addr == MAP_FAILED)
       errExit("mmap");

    printf("Address returned by mmap() = %p\n", mmap_addr);

    /* Register the memory range of the mapping we just created for
      handling by the userfaultfd object. In mode, we request to track
      missing pages (i.e., pages that have not yet been faulted in). */

    uffdio_register.range.start = (unsigned long) mmap_addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
       errExit("ioctl-UFFDIO_REGISTER");

    /* Main thread now touches memory in the mapping, touching
      locations 1024 bytes apart. This will trigger userfaultfd
      events for all pages in the region. */

    int l;
    l = 0xf;    /* Ensure that faulting address is not on a page
                  boundary, in order to test that we correctly
                  handle that case in fault_handling_thread() */
    while (l < len) {
       char c = mmap_addr[l];
       printf("Read address %p in main(): ", mmap_addr + l);
       printf("%c\n", c);
       l += 1024;
       usleep(100000);         /* Slow things down a little */
    }

    exit(EXIT_SUCCESS);
}
