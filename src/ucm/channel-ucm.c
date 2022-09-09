#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "channel-ucm.h"

int channel_server_init()
{
    int fd = -1;
    struct sockaddr_un server_addr;
    int ret;

    /* unix socket server */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        perror("socket");
        return fd;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    snprintf(&server_addr.sun_path[1],
            sizeof(server_addr.sun_path) - 1,
            "server.sock");

    ret = bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret != 0) {
        close(fd);
        perror("bind");
        return -1;
    }

    ret = listen(fd, MAX_BACKLOG);
    if (ret != 0) {
        close(fd);
        perror("listen");
        return -1;
    }

    return fd;
}
