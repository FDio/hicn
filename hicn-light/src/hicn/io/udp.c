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
 * @file udp.c
 * #brief Implementation of the UDP face
 *
 * Old comment:
 * - The Send() function may overflow the output buffer
 *
 */

/* This has to be included early as other modules are including socket.h */

#ifndef _WIN32
#include <arpa/inet.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sys/uio.h>
#include <unistd.h>
#endif
#include <sys/socket.h>

#ifdef WITH_GSO
#include <netinet/if_ether.h>  // ETH_DATA_LEN
#include <linux/ipv6.h>        // struct ipv6hdr
#include <netinet/udp.h>       // struct udphdr, SOL_UDP
//#include <linux/udp.h> // UDP_GRO
#define UDP_GRO 104
#endif /* WITH_GSO */

#include <hicn/util/log.h>
#include <hicn/util/sstrncpy.h>
#include <hicn/util/ring.h>

#include "base.h"
#include "../core/address_pair.h"
#include "../core/connection.h"
#include "../core/connection_vft.h"
#include "../core/forwarder.h"
#include "../core/listener.h"
#include "../core/listener_vft.h"
#include "../core/messageHandler.h"
#include "../core/msgbuf.h"
//#include "../hicn-light/config.h"

// Batching based on recvmmsg is also generic
// the difference is the handling of packet as in tcp we need to go through the
// ring buffer first to do the framing, while in UDP this is already done
//
// each module should have a function to process a packet, then call a callback
// in the forwarder again

#define BATCH_SOCKET_BUFFER 512 * 1024 /* 256k */

/******************************************************************************
 * Listener
 ******************************************************************************/

typedef struct {
  uint16_t port;  // in address ?
} listener_udp_data_t;

#ifdef __ANDROID__
extern int bindSocket(int sock, const char *interface_name);
#endif

#if 0
#include <arpa/inet.h>
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen) {
  switch (sa->sa_family) {
    case AF_INET:
      inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr), s, maxlen);
      break;

    case AF_INET6:
      inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr), s, maxlen);
      break;

    default:
      strncpy(s, "Unknown AF", maxlen);
      return NULL;
  }

  return s;
}
#endif

/* socket options */
int socket_set_options(int fd) {
#ifndef _WIN32
  // Set non-blocking flag
  int flags = fcntl(fd, F_GETFL, NULL);
  if (flags < 0) {
    perror("fcntl");
    return -1;
  }

  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    perror("fcntl");
    return -1;
  }
#else
  // Set non-blocking flag
  int result = ioctlsocket(fd, FIONBIO, &(int){1});
  if (result != NO_ERROR) {
    perror("ioctlsocket");
    return -1;
  }
#endif

  // don't hang onto address after listener has closed
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)) < 0) {
    perror("setsockopt");
    return -1;
  }

#ifdef WITH_GSO
  int gso_size = ETH_DATA_LEN - sizeof(struct ipv6hdr) - sizeof(struct udphdr);
  if (setsockopt(fd, SOL_UDP, UDP_SEGMENT, &gso_size, sizeof(gso_size)) < 0) {
    perror("setsockopt");
    return -1;
  }
#endif /* WITH_GSO */

#ifdef WITH_GRO
  if (setsockopt(fd, IPPROTO_UDP, UDP_GRO, &(int){1}, sizeof(int)) < 0) {
    perror("setsockopt");
    return -1;
  }
#endif /* WITH_GRO */

#ifdef WITH_ZEROCOPY
  if (setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &(int){1}, sizeof(int))) {
    perror("setsockopt");
    return -1;
  }
#endif /* WITH_ZEROCOPY */

  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &(int){BATCH_SOCKET_BUFFER},
                 sizeof(int)) < 0) {
    perror("setsockopt");
    return -1;
  }
  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &(int){BATCH_SOCKET_BUFFER},
                 sizeof(int)) < 0) {
    perror("setsockopt");
    return -1;
  }
  return 0;
}

#ifdef __linux__
/* bind to device */
int socket_bind_to_device(int fd, const char *interface_name) {
  if (strncmp("lo", interface_name, 2) == 0) return 0;

  if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface_name,
                 strnlen_s(interface_name, IFNAMSIZ)) < 0) {
    perror("setsockopt");
    goto ERR_BIND_TO_DEVICE;
  }

  return 0;

ERR_BIND_TO_DEVICE:
#ifdef __ANDROID__
  if (bindSocket(fd, interface_name) < 0) return -1;
  return 0;
#else
  return -1;
#endif /* __ANDROID__ */
}
#endif /* __linux__ */

static int listener_udp_initialize(listener_t *listener) {
  assert(listener);

#if 0
    listener_udp_data_t * data = listener->data;
    assert(data);
#endif
  return 0;
}

static void listener_udp_finalize(listener_t *listener) {
  assert(listener);
  assert(listener->type == FACE_TYPE_UDP_LISTENER);

  return;
}

static int listener_udp_punt(const listener_t *listener, const char *prefix_s) {
  return -1;
}

static int listener_udp_get_socket(const listener_t *listener,
                                   const address_t *local,
                                   const address_t *remote,
                                   const char *interface_name) {
  int fd = socket(address_family(local), SOCK_DGRAM, 0);
  if (fd < 0) goto ERR_SOCKET;

  if (socket_set_options(fd) < 0) {
    goto ERR;
  }

  if (bind(fd, address_sa(local), address_socklen(local)) < 0) {
    perror("bind");
    goto ERR;
  }

#ifdef __linux__
  if (socket_bind_to_device(fd, interface_name) < 0) {
    goto ERR;
  }
#endif /* __linux__ */

  // DEBUG("UDP remote ?");
  if (remote) {
    // DEBUG("UDP connected socket ");
    if (connect(fd, address_sa(remote), address_socklen(remote)) < 0) {
      perror("connect");
      goto ERR;
    }
  }

  return fd;

ERR:
#ifndef _WIN32
  close(fd);
#else
  closesocket(fd);
#endif
ERR_SOCKET:
  return -1;
}

#define listener_udp_read_single io_read_single_socket

#ifdef __linux__
#define listener_udp_read_batch io_read_batch_socket
#else
#define listener_udp_read_batch NULL
#endif /* __linux__ */

DECLARE_LISTENER(udp);

/******************************************************************************
 * Connection
 ******************************************************************************/

#define RING_LEN 5 * MAX_MSG

typedef struct {
  /*
   * Ring buffer
   *
   * This is sized to more than a batch to cope with transient failures of
   * sendmmsg.
   */
  off_t *ring;

#ifdef __linux__
  struct mmsghdr msghdr[MAX_MSG];
  struct iovec iovecs[MAX_MSG];
#endif /* __linux__ */
} connection_udp_data_t;

static int connection_udp_initialize(connection_t *connection) {
  assert(connection);
  assert(connection->type == FACE_TYPE_UDP);
  assert(connection->interface_name);

#ifdef __linux__
  connection_udp_data_t *data = connection->data;
  assert(data);

  ring_init(data->ring, RING_LEN);

  void *name = NULL;
  int namelen = 0;

  /*
   * If the connection does not use a connected socket, we need to set the
   * different destination addresses
   */
  if (!connection->connected) {
    const address_t *remote = connection_get_remote(connection);
    name = address_sa(remote);
    namelen = address_socklen(remote);
  }

  memset(data->msghdr, 0, MAX_MSG * sizeof(struct mmsghdr));
  for (unsigned i = 0; i < MAX_MSG; i++) {
    struct mmsghdr *msg = &data->msghdr[i];
    *msg = (struct mmsghdr){
        .msg_hdr =
            {
                .msg_iov = &data->iovecs[i],
                .msg_iovlen = 1,
                .msg_name = name,
                .msg_namelen = namelen,
#if 0
                .msg_control = NULL,
                .msg_controllen = 0,
                .msg_flags = 0,
#endif
            },
    };
  }
#endif /* __linux__ */

  return 0;
}

static void connection_udp_finalize(connection_t *connection) {
  assert(connection);
  assert(connection->type == FACE_TYPE_UDP);

  connection_udp_data_t *data = connection->data;
  assert(data);

  ring_free(data->ring);
}

static bool connection_udp_flush(connection_t *connection) {
#ifdef __linux__
  int retry = 0;
  off_t msgbuf_id = 0;
  unsigned cpt;
  size_t i;
  int n;

  assert(connection);
  forwarder_t *forwarder = listener_get_forwarder(connection->listener);
  msgbuf_pool_t *msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
  connection_udp_data_t *data = connection->data;
  assert(data);

  TRACE("[connection_udp_send] Flushing connection queue");

  /* Flush operation */
#ifdef WITH_ZEROCOPY
  int flags = MSG_ZEROCOPY;
#else
  int flags = 0;
#endif /* WITH_ZEROCOPY */

SEND:
  /* Consume up to MSG_MSG packets in ring buffer */
  cpt = 0;

  ring_enumerate_n(data->ring, i, &msgbuf_id, MAX_MSG, {
    msgbuf_t *msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);

    // update path label
    if (msgbuf_get_type(msgbuf) == MSGBUF_TYPE_DATA) {
      msgbuf_update_pathlabel(msgbuf, connection_get_id(connection));

      connection->stats.data.tx_pkts++;
      connection->stats.data.tx_bytes += msgbuf_get_len(msgbuf);
    } else {
      connection->stats.interests.tx_pkts++;
      connection->stats.interests.tx_bytes += msgbuf_get_len(msgbuf);
    }

    data->iovecs[i].iov_base = msgbuf_get_packet(msgbuf);
    data->iovecs[i].iov_len = msgbuf_get_len(msgbuf);
    cpt++;
  });

SENDMMSG:
  n = sendmmsg(connection->fd, data->msghdr, cpt, flags);
  if (n == -1) {
    /* man(2)sendmmsg / BUGS
     *
     * If an error occurs after at least one message has been sent, the call
     * succeeds, and returns the number of messages sent.  The error code is
     * lost.  The caller can retry the transmission, starting at the first
     * failed message, but there is no guarantee that, if an error is
     * returned, it will be the same as the one that was lost on the previous
     * call.
     */
    WARN("sendmmsg failed %s", strerror(errno));
    if (retry < 1) {
      retry++;
      goto SENDMMSG;
    }
    return false;
  }

  ring_advance(data->ring, n);

  if (n < cpt) {
    WARN("Unknown error after sending n=%d packets...", n);
    if (retry < 1) {
      retry++;
      goto SEND;
    }
  }

  if (ring_get_size(data->ring) > 0) {
    retry = 0;
    goto SEND;
  }
#endif /* __linux__ */
  return true;
}

/**
 * @function metisUdpConnection_Send
 * @abstract Non-destructive send of the message.
 * @discussion
 *   sends a message to the peer.
 *
 * @param dummy is ignored.  A udp connection has only one peer.
 * @return <#return#>
 */
static bool connection_udp_send(connection_t *connection, msgbuf_t *msgbuf,
                                bool queue) {
  assert(connection);
  assert(msgbuf);

#ifdef __linux__
  connection_udp_data_t *data = connection->data;
  assert(data);

  forwarder_t *forwarder = listener_get_forwarder(connection->listener);
  msgbuf_pool_t *msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);

  /* Queue packet ? */
  if (queue) {
    off_t msgbuf_id;
    if (ring_is_full(data->ring)) connection_udp_flush(connection);

    msgbuf_id = msgbuf_pool_get_id(msgbuf_pool, msgbuf);
    ring_add(data->ring, &msgbuf_id);

  } else {
#endif /* __linux__ */
    /* Send one */
    // update the path label befor send the packet
    if (msgbuf_get_type(msgbuf) == MSGBUF_TYPE_DATA) {
      msgbuf_update_pathlabel(msgbuf, connection_get_id(connection));

      connection->stats.data.tx_pkts++;
      connection->stats.data.tx_bytes += msgbuf_get_len(msgbuf);
    } else {
      connection->stats.interests.tx_pkts++;
      connection->stats.interests.tx_bytes += msgbuf_get_len(msgbuf);
    }

    ssize_t writeLength = write(connection->fd, msgbuf_get_packet(msgbuf),
                                msgbuf_get_len(msgbuf));

    if (writeLength < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return false;
      } else {
        // this print is for debugging
        printf("Incorrect write length %zd, expected %u: (%d) %s\n",
               writeLength, msgbuf_get_len(msgbuf), errno, strerror(errno));
        return false;
      }
    }
#ifdef __linux__
  }
#endif /* __linux__ */

  return true;
}

#if 0
static
bool
connection_udp_sendv(const connection_t * connection, struct iovec * iov,
        size_t size)
{

    assert(connetion);
    assert(iov);

    connection_udp_data_t * data = connection->data;
    assert(data);

#ifndef _WIN32
    // Perform connect before to establish association between this peer and
    // the remote peer. This is required to use writev.
    // Connection association can be changed at any time.

    if (writev(connection->fd, iov, (int)size) < 0)
        return false;
#else
    WSABUF *buf = (WSABUF *) malloc(size * sizeof(WSABUF));

    DWORD bytes_sent = 0;

    for (int i = 0; i < size; i++) {
        buf[i].buf = iov[i].iov_base;
        buf[i].len = (ULONG)iov[i].iov_len;
    }

    int rc = WSASendTo(udp->fd, buf, size, &bytes_sent, 0,
            (SOCKADDR *)address_sa(address_pair_remote(&udp->pair)),
            address_socklen(address_pair_remote(&udp->pair)), NULL, NULL);
    free(dataBuf);
    if (rc == SOCKET_ERROR)
        return false;
#endif

    return true;
}
#endif

static int connection_udp_send_packet(const connection_t *connection,
                                      const uint8_t *packet, size_t size) {
  assert(connection);
  assert(packet);

  // XXX: in case of two connections this functions may have wrong behaviour. We
  // noticed that the packet is sent by the forwarder on the right socket (fd)
  // but from tcpdump we see that the packet goes on the other connection. In
  // other cases the packet is sent twice, first on the wrong socket and later
  // on the right one, even if we log a single send from the forwarder. The
  // same behaviour was observed with the write executed in the function
  // connection_udp_send with the queue flag set to false. A workaround that
  // seems to solve the problem is to use connection_udp_send with queue = true
  // and force the flush of the connection if needed.

  // TODO: commented otherwise unable to do tests locally
  // if(connection_is_local(connection))
  //     return -1;

#ifdef USE_CONNECTED_SOCKETS
  ssize_t n = send(connection->fd, packet, size, 0);
  if (n < 0) {
    perror("sendto");
    return -1;
  }
#else
  const address_t *remote = connection_get_remote(connection);
  ssize_t n = sendto(connection->fd, packet, size, 0, address_sa(remote),
                     address_socklen(remote));
  if (n < 0) return -1;
#endif

  return 0;
}

#define connection_udp_read_single \
  listener_read_batch_socket listener_single_socket

#ifdef __linux__
#define connection_udp_read_batch listener_read_batch_socket
#else
#define connection_udp_read_batch NULL
#endif /* __linux__ */

DECLARE_CONNECTION(udp);
