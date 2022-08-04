/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

    msgbuf_set_len(msgbuf, (size_t)n);
    *address = ADDRESS_ANY(AF_UNSPEC, 0);  // XXX placeholder, see hicn.c
  }

  return 1;
}

ssize_t io_read_single_socket(int fd, msgbuf_t *msgbuf, address_t *address) {
  struct sockaddr *sa = &(address->as_sa);
  socklen_t sa_len = sizeof(sa);
  uint8_t *packet = msgbuf_get_packet(msgbuf);

  ssize_t n = recvfrom(fd, packet, MTU, 0, (struct sockaddr *)sa, &sa_len);
  msgbuf_set_len(msgbuf, (size_t)n);

#ifdef __APPLE__
  // set __uint8_t sin_len to 0
  uint8_t *ptr = (uint8_t *)sa;
  *ptr = 0x0;
#endif /* __APPLE__ */

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
    // INFO("Got n=%d messages", n);
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
      msgbuf_set_len(msgbuf[i], msg->msg_len);

      memcpy(address[i], msg->msg_hdr.msg_name, msg->msg_hdr.msg_namelen);
    }
    break;
  }

  return n;
}
#endif /* __linux__ */
