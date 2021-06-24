/*
 * Dummy server sending alternating bytes to all clients.
 *
 * This program can be used to trigger mobility events in the hICN forwarder, to
 * switch from WiFi to LTE and back, at regular intervals.
 *
 * Test server using nc: nc -4kvul localhost 9533
 */

#include <arpa/inet.h> // inet_ntop
#include <errno.h> // EINTR,. ..
#include <netinet/in.h> // INET_ADDRSTRLEN, INET6_ADDRSTRLEN
#include <stdio.h>
#include <inttypes.h>

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/un.h> // sockaddr_un
#include <unistd.h> // fcntl
#include <fcntl.h> // fcntl

#define MS2US(x) (x * 1000)

/**
 * \brief Main function
 */
int main(int argc, char **argv)
{
    int rc;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s IP PORT INTERVAL\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "    IP       Target hostname\n");
        fprintf(stderr, "    PORT     Target port\n");
        fprintf(stderr, "    INTERVAL Interval between mobility events (in ms)\n");
        fprintf(stderr, "\n");
        exit(EXIT_FAILURE);
    }

    int interval = atoi(argv[3]);

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        perror("socket");
        goto ERR_SOCKET;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(argv[1]);
    addr.sin_port = htons(atoi(argv[2]));

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        goto ERR_CONNECT;
    }

    unsigned state = 0;
    char buf[1];
    for(;;) {
        usleep(MS2US(interval));

        buf[0] = state;
        rc = send(fd, buf, 1, 0);
        if (rc < 0) {
            if (errno == ECONNREFUSED) {
                continue;
            }
            perror("send");
            goto ERR_SEND;
        }

        state = 1 - state;
    }

    close(fd);

    exit(EXIT_SUCCESS);

ERR_SEND:
ERR_CONNECT:
    close(fd);
ERR_SOCKET:
    exit(EXIT_FAILURE);
}
