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

static int page_size;

int main()
{
    static struct uffd_msg msg;   /* Data read from userfaultfd */
    struct uffdio_copy uffdio_copy;
    ssize_t nread;
    struct pollfd pollfd;
    int nready;
    int page_size;
    int fd;
    long uffd;
    int len;
    struct sockaddr_un addr;
    struct sockaddr_un from;
    socklen_t fromlen = sizeof(from);

    // unix socket, get uffd, source addr and page size
    fd = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        errExit("socket");
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SERVER_SOCK_FILE);
    unlink(SERVER_SOCK_FILE);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        errExit("bind");
    }

    // receive the uffd
    uffd = recv_fd(fd);
    if (uffd < 0) {
        errExit("recv");        
    }

    if (fd >= 0) {
        close(fd);
    }

    printf("the received uffd on the ucm side:%ld\n", uffd);
    pollfd.fd = uffd;
    pollfd.events = POLLIN;
    page_size = sysconf(_SC_PAGE_SIZE);

   // source address
    char *page = NULL;
    /* Create a page that will be copied into the faulting region */

    if (page == NULL) {
       page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
       if (page == MAP_FAILED)
           errExit("mmap");
    }

     /* Copy the page pointed to by 'page' into the faulting
          region. Vary the contents that are copied in, so that it
          is more obvious that each fault is handled separately. */

    memset(page, 'A', page_size);


    /* Loop, handling incoming events on the userfaultfd
      file descriptor */

    for (;;) {

       /* See what poll() tells us about the userfaultfd */

       nready = poll(&pollfd, 1, -1);
       if (nready == -1)
           errExit("poll");

       printf("    poll() returns: nready = %d; "
               "POLLIN = %d; POLLERR = %d\n", nready,
               (pollfd.revents & POLLIN) != 0,
               (pollfd.revents & POLLERR) != 0);

       /* Read an event from the userfaultfd */

       nread = read(uffd, &msg, sizeof(msg));
       if (nread == 0) {
           printf("EOF on userfaultfd!\n");
           exit(EXIT_FAILURE);
       }

       if (nread == -1)
           errExit("read");

       /* We expect only one kind of event; verify that assumption */

       if (msg.event != UFFD_EVENT_PAGEFAULT) {
           fprintf(stderr, "Unexpected event on userfaultfd\n");
           exit(EXIT_FAILURE);
       }

       /* Display info about the page-fault event */

       printf("    UFFD_EVENT_PAGEFAULT event: ");
       printf("flags = %llu; ", msg.arg.pagefault.flags);
       printf("address = %llu\n", msg.arg.pagefault.address);

       uffdio_copy.src = (unsigned long)page;

       /* We need to handle page faults in units of pages(!).
          So, round faulting address down to page boundary */

       uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                                          ~(page_size - 1);
       uffdio_copy.len = page_size;
       uffdio_copy.mode = 0;
       uffdio_copy.copy = 0;
       if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
           errExit("ioctl-UFFDIO_COPY");

       printf("        (uffdio_copy.copy returned %lld)\n",
               uffdio_copy.copy);
    }
}
