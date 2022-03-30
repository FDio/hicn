/*
 * Dummy server sending alternating bytes to all clients.
 *
 * This is used by the face manager to illustrate the creation of interfaces
 * using unix domains that sets a face up and down.
 */

#include <arpa/inet.h>   // inet_ntop
#include <errno.h>       // EINTR,. ..
#include <netinet/in.h>  // INET_ADDRSTRLEN, INET6_ADDRSTRLEN
#include <stdio.h>
#include <inttypes.h>

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/un.h>  // sockaddr_un
#include <unistd.h>  // fcntl
#include <fcntl.h>   // fcntl

#include <hicn/util/sstrncpy.h>

/**
 * \brief Default unix socket path (the leading \0 means using the abstract
 * namespace instead of the filesystem).
 */
#define UNIX_PATH "\0updownsrv"

/**
 * \brief Default interval (in seconds) between timer events */
#define DEFAULT_INTERVAL_SEC 5
#define DEFAULT_INTERVAL_NSEC 0

/**
 * \brief Maximum allowed number of connected clients
 */
#define MAX_CLIENTS 5

/**
 * \brief Maximum backlog of listening unix socket
 */
#define LISTEN_BACKLOG MAX_CLIENTS

/**
 * \brief Creates a unix server socket
 * \param [in] path - string representing the path on which to listen for
 *      connections
 * \return int - fd associated to the socket
 */
int create_unix_server(char* path) {
  struct sockaddr_un addr;
  int fd;

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd == -1) {
    perror("socket error");
    return -1;
  }

  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
    perror("fcntl");
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (*path == '\0') {
    *addr.sun_path = '\0';
    strcpy_s(addr.sun_path + 1, sizeof(addr.sun_path) - 2, path + 1);
  } else {
    strcpy_s(addr.sun_path, sizeof(addr.sun_path) - 1, path);
    unlink(path);
  }

  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    perror("bind error");
    return -1;
  }

  if (listen(fd, LISTEN_BACKLOG) == -1) {
    perror("listen error");
    return -1;
  }

  return fd;
}

/**
 * \brief Main function
 */
int main() {
  int fd, tfd;
  int rc;

  /* Alternating state of the server : 0 / 1 */
  unsigned state = 0;

  /*
   * This server has to send a signal to all connected clients at periodic
   * intervals. Since we don't expect a large number of connected clients for
   * such a simple program, we simply use a statically allocated array.
   */
  int clients[MAX_CLIENTS];
  size_t num_clients = 0;

  fd_set active_fd_set, read_fd_set;
  FD_ZERO(&active_fd_set);

  /* Create listening unix socket */
  fd = create_unix_server(UNIX_PATH);
  if (fd < 0) exit(EXIT_FAILURE);

  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
    perror("fcntl");
    exit(EXIT_FAILURE);
  }

  FD_SET(fd, &active_fd_set);

  /* Create timer */
  tfd = timerfd_create(CLOCK_MONOTONIC, 0);
  if (tfd == -1) {
    perror("timer error");
    exit(EXIT_FAILURE);
  }

  if (fcntl(tfd, F_SETFL, O_NONBLOCK) < 0) {
    perror("fcntl");
    exit(EXIT_FAILURE);
  }

  FD_SET(tfd, &active_fd_set);

  struct itimerspec ts = {.it_interval =
                              {
                                  .tv_sec = DEFAULT_INTERVAL_SEC,
                                  .tv_nsec = DEFAULT_INTERVAL_NSEC,
                              },
                          .it_value = {
                              .tv_sec = DEFAULT_INTERVAL_SEC,
                              .tv_nsec = DEFAULT_INTERVAL_NSEC,
                          }};
  rc = timerfd_settime(tfd, 0, &ts, NULL);
  if (rc == -1) {
    perror("timerfd_settime");
    exit(EXIT_FAILURE);
  }

  printf("Waiting for clients...\n");

  for (;;) {
    /* Block until input arrives on one or more active sockets. */
    read_fd_set = active_fd_set;
    rc = select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL);
    if (rc < 0) {
      if (rc == EINTR) break;
      perror("select");
      exit(EXIT_FAILURE);
    }

    /* Service all the sockets with input pending. */
    for (int i = 0; i < FD_SETSIZE; ++i) {
      if (!FD_ISSET(i, &read_fd_set)) continue;
      if (i == fd) {
        /* Connection request on original socket. */
        int client_fd = accept(fd, NULL, NULL);
        if (client_fd < 0) {
          perror("accept");
          continue;
        }

        fprintf(stderr, "Server: connect from new client\n");
        clients[num_clients++] = client_fd;
        FD_SET(client_fd, &active_fd_set);
      } else if (i == tfd) {
        /* Timer event */
        uint64_t res;

        read(tfd, &res, sizeof(res));
        //                while (read(fd, &missed, sizeof(missed)) > 0)
        //                    ;
        for (unsigned j = 0; j < num_clients; j++) {
          write(clients[j], state ? "\1" : "\0", 1);
        }
        printf("STATE=%d\n", state);
        state = 1 - state;
      } else {
        char buf[1024];
        rc = read(i, buf, sizeof(buf));
        /* Client event : we close the connection on any event... */
        for (unsigned j = 0; j < num_clients; j++) {
          if (i == clients[j]) {
            clients[j] = clients[num_clients--];
            break;
          }
        }
        close(i);
        FD_CLR(i, &active_fd_set);
      }
    }
  }

  int ret = EXIT_SUCCESS;

  /* Close all active client connections */
  for (unsigned i = 0; i < num_clients; i++) {
    rc = close(clients[i]);
    if (rc == -1) {
      perror("close");
      ret = EXIT_FAILURE;
    }
  }

  /* Close server */
  rc = close(fd);
  if (rc == -1) {
    perror("close");
    ret = EXIT_FAILURE;
  }

  /* Terminate timer */
  ts.it_value.tv_sec = 0;
  rc = timerfd_settime(tfd, 0, &ts, NULL);
  if (rc == -1) {
    perror("timerfd_settime");
    exit(EXIT_FAILURE);
  }

  exit(ret);
}
