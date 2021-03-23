/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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
#include <netinet/if_ether.h> // ETH_DATA_LEN
#include <linux/ipv6.h> // struct ipv6hdr
#include <netinet/udp.h> // struct udphdr, SOL_UDP
//#include <linux/udp.h> // UDP_GRO
#define UDP_GRO 104
#endif /* WITH_GSO */

#include <hicn/util/log.h>

#include "base.h"
#include "../base/loop.h"
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
  uint16_t port; // in address ?
} listener_udp_data_t;

#ifdef __ANDROID__
extern int bindSocket(int sock, const char * interface_name);
#endif

#include <arpa/inet.h>
char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                    s, maxlen);
            break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                    s, maxlen);
            break;

        default:
            strncpy(s, "Unknown AF", maxlen);
            return NULL;
    }

    return s;
}

/* socket options */
int
socket_set_options(int fd)
{
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
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    perror("setsockopt");
    return -1;
 }

#ifdef WITH_GSO
//● choosing gso_size
//○ ETH_DATA_LEN
//○ IP_MTU_DISCOVER
//● choosing number of segments
//○ fit in network layer
//○ <= UDP_MAX_SEGMENTS
//○ > gso_size
//● checksum offload
//○ csum_and_copy_from_user
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

  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &(int){BATCH_SOCKET_BUFFER}, sizeof(int)) < 0) {
    perror("setsockopt");
    return -1;
  }
  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &(int){BATCH_SOCKET_BUFFER}, sizeof(int)) < 0) {
    perror("setsockopt");
    return -1;
  }
  return 0;
}

#ifdef __linux__
/* bind to device */
int
socket_bind_to_device(int fd, const char * interface_name)
{
  if (strncmp("lo", interface_name, 2) == 0)
    return 0;

  if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface_name,
              strlen(interface_name) + 1) < 0) {
      perror("setsockopt");
      goto ERR_BIND_TO_DEVICE;
  }

  return 0;

ERR_BIND_TO_DEVICE:
#ifdef __ANDROID__
  if (bindSocket(fd, interface_name) < 0)
      return -1;
  return 0;
#else
  return -1;
#endif /* __ANDROID__ */
}
#endif /* __linux__ */

static
int
listener_udp_initialize(listener_t * listener)
{
    assert(listener);

#if 0
    listener_udp_data_t * data = listener->data;
    assert(data);
#endif

    // XXX Socket creation should be a function per-se and not be called in
    // initialize !
    listener->fd = listener_get_socket(listener, &listener->address, NULL,
            listener->interface_name);
    if (listener->fd < 0) {
        ERROR("Error creating UDP socket: (%d) %s", errno, strerror(errno));
        return -1;
    }
    return 0;
}

static
void
listener_udp_finalize(listener_t * listener)
{
    assert(listener);
    assert(listener_get_type(listener) == FACE_TYPE_UDP);

    return;
}

static
int
listener_udp_punt(const listener_t * listener, const char * prefix_s)
{
    return -1;
}

static
int
listener_udp_get_socket(const listener_t * listener, const address_t * local,
        const address_t * remote, const char * interface_name)
{
    int fd = socket(address_family(local), SOCK_DGRAM, 0);
    if (fd < 0)
        goto ERR_SOCKET;

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

    if (remote) {
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

typedef struct {
    // XXX queue storage : msfbuf id
    off_t queue[MAX_MSG]; // sized according to the max batch
    int queue_len;
} connection_udp_data_t;

static
int
connection_udp_initialize(connection_t * connection)
{

    assert(connection);
    assert(connection->type == FACE_TYPE_UDP || connection->type == FACE_TYPE_UDP_LISTENER);
    assert(connection->interface_name);

    connection_udp_data_t * data = connection->data;
    assert(data);

    data->queue_len = 0;

    return 0;
}

static
void
connection_udp_finalize(connection_t * connection)
{
    ERROR("[connection_udp_finalize] Not implemented");

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
// XXX address not used anywhere
static
int
connection_udp_send(const connection_t * connection, msgbuf_t * msgbuf, bool queue)
{
    assert(connection);
    /* msgbuf can be NULL */

    connection_udp_data_t * data = connection->data;
    assert(data);

    forwarder_t * forwarder = connection->forwarder;
    msgbuf_pool_t * msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);


    /* Flush if required or if queue is full */
    if ((!msgbuf) || (queue && (data->queue_len > MAX_MSG)))  {
        /* Flush operation */
#ifdef WITH_ZEROCOPY
        int flags = MSG_ZEROCOPY;
#else
        int flags = 0;
#endif /* WITH_ZEROCOPY */


        // BEGIN : send batch

        /* Preparing the struct mmsghdr for batch sending */
        struct mmsghdr msghdr[MAX_MSG];
        struct iovec iovecs[MAX_MSG];

        /* Prepare the mmghdr struct for recvmmsg */
        for (unsigned i = 0; i < data->queue_len; i++) {
             struct mmsghdr *msg = &msghdr[i];
            *msg = (struct mmsghdr) {
                .msg_hdr = {
                    .msg_iov = &iovecs[i],
                    .msg_iovlen = 1,
                    .msg_name = NULL,
                    .msg_namelen = 0,
                    .msg_control = NULL,
                    .msg_controllen = 0,
                },
            };

            msgbuf_t * msgbuf = msgbuf_pool_at(msgbuf_pool, data->queue[i]);
            iovecs[i] = (struct iovec) {
                .iov_base = msgbuf_get_packet(msgbuf),
                .iov_len = msgbuf_get_len(msgbuf),
            };
        }

        // XXX build mmsghdr from the msgbuf queue

        int n = sendmmsg(connection->fd, msghdr, data->queue_len, flags);
        if (n == -1) {
            perror("sendmmsg()");
            data->queue_len = 0;
            return false;
        }

        if (n < data->queue_len) {
            // XXX TODO
            printf("Unhandled Error after sending n=%d msgbufs\n", n);
        }

        /* XXX check msglen */
        data->queue_len = 0;
        return true;
    }

    if (queue) {
        /* Queue packet */
        data->queue[data->queue_len++] = msgbuf_pool_get_id(msgbuf_pool, msgbuf);
    } else {
        /* Send one */
        ssize_t writeLength = write(connection->fd, msgbuf_get_packet(msgbuf),
                msgbuf_get_len(msgbuf));

        if (writeLength < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return false;
            } else {
                // this print is for debugging
                printf("Incorrect write length %zd, expected %u: (%d) %s\n", writeLength,
                        msgbuf_get_len(msgbuf), errno, strerror(errno));
                return false;
            }
        }
    }

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

static
int
connection_udp_send_packet(const connection_t * connection, const uint8_t * packet, size_t size)
{
    assert(connection);
    assert(packet);

    if(connection_is_local(connection))
        return -1;

    ssize_t n = sendto(connection->fd, packet, size, 0,
            address_sa(address_pair_get_remote(&connection->pair)),
            address_socklen(address_pair_get_remote(&connection->pair)));
    if (n < 0)
        return -1;
    return 0;
}

#define connection_udp_read_single listener_read_batch_socket listener_single_socket

#ifdef __linux__
#define connection_udp_read_batch listener_read_batch_socket
#else
#define connection_udp_read_batch NULL
#endif /* __linux__ */


DECLARE_CONNECTION(udp);
