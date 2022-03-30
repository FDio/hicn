#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <hicn/util/sstrncpy.h>

/**
 * \brief Default unix socket path (the leading \0 means using the abstract
 * namespace instead of the filesystem).
 */
#define UNIX_PATH "\0updownsrv"

int main() {
  struct sockaddr_un addr;
  char buf[100];
  int fd, rc;

  char* socket_path = UNIX_PATH;

  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket error");
    exit(-1);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (*socket_path == '\0') {
    *addr.sun_path = '\0';
    strcpy_s(addr.sun_path + 1, sizeof(addr.sun_path) - 2, socket_path + 1);
  } else {
    strcpy_s(addr.sun_path, sizeof(addr.sun_path) - 1, socket_path);
  }

  if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    perror("connect error");
    exit(-1);
  }

  printf("Waiting for server data...\n");
  while ((rc = read(fd, buf, sizeof(buf))) > 0) {
    assert(rc == 1);
    switch (buf[0]) {
      case '\0':
        printf("WiFi\n");
        break;
      case '\1':
        printf("LTE\n");
        break;
      default:
        printf("Unknown\n");
        break;
    }
  }

  return 0;
}
