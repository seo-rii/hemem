#include <unistd.h>
#include "channel-app.h"

int channel_client_init(enum channel_type type)
{
    int fd = -1;
    struct sockaddr_un client_addr;
    struct sockaddr_un server_addr;

    /* unix socket client */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        perror("socket");
        return -1;
    }

    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sun_family = AF_UNIX;
    snprintf(&client_addr.sun_path[1],
            sizeof(client_addr.sun_path) - 1,
            "client-%d-%d", type, getpid());
    fprintf(stderr, "Opening client at %s\n", &client_addr.sun_path[1]);

    if (bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        close(fd);
        perror("bind");
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    snprintf(&server_addr.sun_path[1],
            sizeof(server_addr.sun_path) - 1,
            "server.sock");
    if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        close(fd);
        perror("connect");
        return -1;
    }

    return fd;
}
