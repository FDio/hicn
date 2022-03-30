/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file base.c
 * #brief Implementation of base IO functions.
 */

#include <hicn/util/log.h>

#include "base.h"

/**
 * @brief Helper function for listener to read a single packet on a socket
 */
ssize_t io_read_single_fd(int fd, msgbuf_t *msgbuf, address_t *address) {
  uint8_t *packet = msgbuf_get_packet(msgbuf);
  size_t size = msgbuf_get_len(msgbuf);

  for (;;) {
    ssize_t n = read(fd, packet, size);
    if (n == 0) return n;
    if (n < 0) {
      if (errno == EINTR) continue;  // XXX was break;

      /* ICMP unreachable due to closing the remote end of a connection */
      if (errno == ECONNREFUSED) continue;

      ERROR("read failed %d: (%d) %s", fd, errno, strerror(errno));
      return -1;
    }

    msgbuf->length = n;
    *address = ADDRESS_ANY(AF_UNSPEC, 0);  // XXX placeholder, see hicn.c
  }

  return 1;
}

ssize_t io_read_single_socket(int fd, msgbuf_t *msgbuf, address_t *address) {
  struct sockaddr_storage *sa = &address->as_ss;
  socklen_t sa_len = sizeof(sa);
  uint8_t *packet = msgbuf_get_packet(msgbuf);

  ssize_t n = recvfrom(fd, packet, MTU, 0, (struct sockaddr *)sa, &sa_len);
  msgbuf->length = n;

  return n;
}

#ifdef __linux__
ssize_t io_read_batch_socket(int fd, msgbuf_t **msgbuf, address_t **address,
                             size_t batch_size) {
  struct mmsghdr msghdr[batch_size];
  struct iovec iovecs[batch_size];
  struct sockaddr_storage addrs[batch_size];

  /* Prepare the mmghdr struct for recvmmsg */
  for (unsigned i = 0; i < MAX_MSG; i++) {
    struct mmsghdr *msg = &msghdr[i];
    *msg = (struct mmsghdr){
        .msg_hdr =
            {
                .msg_iov = &iovecs[i],
                .msg_iovlen = 1,
                .msg_name = &addrs[i],
                .msg_namelen = sizeof(struct sockaddr_storage),
                .msg_control = NULL,
                .msg_controllen = 0,
            },
    };

    iovecs[i] = (struct iovec){
        .iov_base = msgbuf_get_packet(msgbuf[i]),
        .iov_len = MTU,
    };
  }

  int n;
  for (;;) {
    n = recvmmsg(fd, msghdr, batch_size, /* flags */ 0,
                 /* timeout */ NULL);
    if (n == 0) return 0;
    if (n < 0) {
      if (errno == EINTR) continue;  // XXX was break;

      /* ICMP unreachable due to closing the remote end of a connection */
      if (errno == ECONNREFUSED) break;
      if (errno == EAGAIN) return n;  // Nothing to read

      ERROR("read failed %d: (%d) %s", fd, errno, strerror(errno));
      return (ssize_t)n;
    }

    /*
     * Assign size to msgbuf, and put the source address into the array
     * received in parameters, which corresponds to the remote parts of the
     * connection (local part is setup in the listener itself, eg.
     * listener_read_batch).
     */
    for (int i = 0; i < n; i++) {
      struct mmsghdr *msg = &msghdr[i];
      msgbuf[i]->length = msg->msg_len;

      /*
       * As is, the address we put in the array has uninitialized
       * memory in it:
       *     *address[i] = *(address_t*)msg->msg_hdr.msg_name;
       *
       * This can be confirmed by testing with the following
       * memset which removes the valgrind errors:
       *     memset(address[i], 0, sizeof(address_t));
       *
       * The solution is to copy only the part which we know is
       * initialized (we have compatible types, since the destination, an
       * address_t, is effectively a struct sockaddr_storage). We might
       * eventually provide a helper for this to avoid similar mistakes.
       */
      //*address[i] = *(address_t*)msg->msg_hdr.msg_name;
      memcpy(address[i], msg->msg_hdr.msg_name, msg->msg_hdr.msg_namelen);
    }
    break;
  }

  return n;
}
#endif /* __linux__ */
