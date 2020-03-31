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
#define _GNU_SOURCE
#include <sys/socket.h>

#ifndef _WIN32
#include <arpa/inet.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <sys/uio.h>
#include <unistd.h>
#endif

#ifdef WITH_GSO
#include <netinet/if_ether.h> // ETH_DATA_LEN
#include <linux/ipv6.h> // struct ipv6hdr
#include <netinet/udp.h> // struct udphdr, SOL_UDP
//#include <linux/udp.h> // UDP_GRO
#define UDP_GRO 104
#endif /* WITH_GSO */

#include <hicn/base/address_pair.h>
#include <hicn/base/connection.h>
#include <hicn/base/listener.h>
#include <hicn/base/loop.h>
#include <hicn/base/msgbuf.h>
#include <hicn/core/messageHandler.h>
#include <hicn/core/messagePacketType.h>
#include <hicn/hicn-light/config.h>
#include <hicn/processor/messageProcessor.h>
#include <hicn/util/log.h>

#include "udp.h"

/******************************************************************************
 * Listener
 ******************************************************************************/

typedef struct {
  uint16_t port; // in address ?

  /* recvmmsg data structures */
  struct mmsghdr msghdr[MAX_MSG]; // XXX = {0};
  char buffers[MAX_MSG][MTU_SIZE];
  struct iovec iovecs[MAX_MSG]; // XXX = {0};
  struct sockaddr_storage addrs[MAX_MSG];
  msgbuf_t messages[MAX_MSG];
  Connection * messages_conn[MAX_MSG];

  uint8_t * commands[MAX_MSG];
  unsigned commands_connid[MAX_MSG];
} listener_udp_data_t;

#ifdef __ANDROID__
extern int bindSocket(int sock, const char* ifname);
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

static void _readcb(listener_t * listener, int fd, void * data)
{
    listener_t * listener = listener_void;
    assert(!data);

    DEBUG("%s socket %d what %s%s%s%s data %p", __func__, fd,
            (what & PARCEventType_Timeout) ? " timeout" : "",
            (what & PARCEventType_Read) ? " read" : "",
            (what & PARCEventType_Write) ? " write" : "",
            (what & PARCEventType_Signal) ? " signal" : "", udp);

    if (!(what & PARCEventType_Read))
        return;

    // XXX potential improvement : receive in a loop while we have messages to
    // read

    int r = recvmmsg(fd, udp->msghdr, MAX_MSG, 0, NULL);
    if (r == 0)
        return;

    if (r < 0) {
        if (errno == EINTR)
            return;
        perror("recv()");
        return;
    }

    int valid = 0;
    int interest_data = 0;
    int commands = 0;

    for (int i = 0; i < r; i++) {
        struct mmsghdr *msg = &udp->msghdr[i];
        uint8_t * packet =  msg->msg_hdr.msg_iov->iov_base;

        /* BEGIN packet processing */

#ifdef __APPLE__
        msg->msg_hdr.msg_namelen = 0x00;
#endif

        /* Construct address pair used for connection lookup */
        address_pair_t pair;
        pair.local = udp->local_addr;
        pair.remote = *(address_t*)msg->msg_hdr.msg_name;

        /* Connection lookup */
        /* Most important here is a fast lookup, insertion removal will less
         * important... */
        connection_table_t * table = forwarder_GetConnectionTable(udp->forwarder);
        Connection ** conn_ptr = connection_table_lookup(table, &pair);
        Connection * conn = *conn_ptr;
        unsigned connid = conn ? connection_table_get_connection_id(table, conn_ptr): CONNECTION_ID_INVALID;

        /* Message type */

        MessagePacketType pktType;
        if (messageHandler_IsTCP(packet)) {
            if (messageHandler_IsData(packet)) {
                if (!conn)
                    continue;
                pktType = MessagePacketType_ContentObject;
            } else if (messageHandler_IsInterest(packet)) {
                if (!conn) {
                    int fd = _getSocket(listener, &pair);
                    connid = _createNewConnection(listener, fd, &pair);
                    // XXX test + conn
                }
                pktType = MessagePacketType_Interest;
            } else {
                continue;
            }
        } else if (messageHandler_IsWldrNotification(packet)) {
            if (!conn)
                continue;
            pktType = MessagePacketType_WldrNotification;
        } else {
            bool processed = forwarder_handleHooks(udp->forwarder, packet, listener, fd, connid, &pair);
            if (processed)
                continue;

            /* Control message ? */
            if (*packet != REQUEST_LIGHT)
                continue;

            if (!conn) {
                int fd = _getSocket(listener, &pair);
                connid = _createNewConnection(listener, fd, &pair);
                // XXX test + conn
            }

            udp->commands[commands] = packet;
            udp->commands_connid[commands++] = connid;
            continue;
        }

        size_t length = messageHandler_GetTotalPacketLength(packet);
        msgbuf_from_packet(&udp->messages[valid], packet, length, pktType, connid, ticks_now());
        udp->messages_conn[valid] = conn;
        valid++;

        if (pktType != MessagePacketType_WldrNotification)
            interest_data++;
    }

    /* Process messages */
    bool first = true;
    for (unsigned i = 0; i < valid; i++) {
        switch(udp->messages[i].packetType) {
            case MessagePacketType_Interest:
            case MessagePacketType_ContentObject:
                forwarder_Receive(udp->forwarder, &udp->messages[i], (first?interest_data:0));
                first = false;
                break;
            case MessagePacketType_WldrNotification:
                connection_HandleWldrNotification(udp->messages_conn[i], &udp->messages[i]);
                break;
        }
    }

    /* Process commands at the end */
    for (unsigned i = 0; i < commands; i++) {
        uint8_t * packet = udp->commands[i];
        unsigned connid = udp->commands_connid[i];
        command_id id = *(packet + 1);
        if (id >= LAST_COMMAND_VALUE)
            continue;
        forwarder_ReceiveCommandBuffer(udp->forwarder, id, packet, connid);
    }

}

int
init_batch_buffers(listener_udp_data_t * data)
{
  /* Setup recvmmsg data structures. */
  for (unsigned i = 0; i < MAX_MSG; i++) {
    char *buf = &data->buffers[i][0];
    struct iovec *iovec = &data->iovecs[i];
    struct mmsghdr *msg = &data->msghdr[i];

    msg->msg_hdr.msg_iov = iovec;
    msg->msg_hdr.msg_iovlen = 1;

    msg->msg_hdr.msg_name = &data->addrs[i];
    msg->msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);

    iovec->iov_base = &buf[0];
    iovec->iov_len = MTU_SIZE;
  }
  return 0;

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
socket_bind_to_device(int fd, const char * interfaceName)
{
  if (strncmp("lo", interfaceName, 2) == 0)
    return 0;

  if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interfaceName,
              strlen(interfaceName) + 1) < 0) {
      perror("setsockopt");
      goto ERR_BIND_TO_DEVICE;
  }

  return 0;

ERR_BIND_TO_DEVICE:
#ifdef __ANDROID__
  if (bindSocket(fd, interfaceName) < 0)
      return -1;
  return 0;
#else
  return -1;
#endif /* __ANDROID__ */
}
#endif /* __linux__ */

// TODO with address
int
listener_udp_make_socket(const address_t * local, const address_t * remote, const char * interfaceName)
{
  int fd = socket(address_family(remote), SOCK_DGRAM, 0);
  if (fd < 0)
    goto ERR_SOCKET;

  if (socket_set_options(fd) < 0) {
    goto ERR;
  }

  if (bind(fd, address_sa(local), address_socklen(remote)) < 0) {
    perror("bind");
    goto ERR;
  }

#ifdef __linux__
  if (socket_bind_to_device(fd, interfaceName) < 0) {
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

static
int
listener_udp_initialize(listener_t * listener)
{
    assert(listener);

    listener_udp_data_t * data = listener->data;
    assert(data);

    init_batch_buffers(data);

    // XXX Socket creation should be a function per-se and not be called in
    // initialize !
    listener->fd = make_socket(address, NULL, interface_name);
    if (listener->fd < 0) {
        ERROR("Error creating UDP socket: (%d) %s", errno, strerror(errno));
        return -1;
    }
    return 0;
}

static
int
listener_udp_finalize(listener_t * listener)
{
    assert(listener);
    assert(listener_get_type(listener) == FACE_TYPE_UDP);

    return 0;
}

static
int
listener_udp_punt(listener_t * listener, const char * prefix_s)
{
    return -1;
}

static
int
listener_udp_get_socket(const listener_t * listener, const address_pair_t * pair)
{
    assert(listener);
    assert(listener_get_type(listener) == FACE_TYPE_UDP);
    assert(pair);

    return make_socket(&pair->local, &pair->remote,
            listener_get_interface_name(listener));

    return fd;
}

DECLARE_LISTENER(udp);

/******************************************************************************
 * Connection
 ******************************************************************************/

typedef struct {
    /* sendmmsg data structures */
    struct mmsghdr msgbufs[MAX_MSG];
    struct iovec iovecs[MAX_MSG];

    int queue_len;
} connection_udp_data_t;

static
int
connection_udp_initialize(connection_t * connection,
        const char * interface_name, int fd, const address_pair_t * pair,
        bool local, unsigned connection_id)
{

    assert(connection);
    assert(connection->type == FACE_TYPE_UDP);
    assert(interface_name);
    assert(address_pair);

    connection_udp_data_t * data = malloc(sizof(connection_udp_data_t));
    if (!data)
        return -1;

    /* Setup sendmmsg data structures. */
    for (unsigned i = 0; i < MAX_MSG; i++) {
        struct mmsghdr *msg = &data->msgbufs[i];
        struct iovec *iovec = &data->iovecs[i];
        msg->msg_hdr.msg_iov = iovec;
        msg->msg_hdr.msg_iovlen = 1;
    }
    data->queue_len = 0;

    connection->data = data;

    return 0;
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
connection_udp_send(const connection_t * connection, const address_t * address,
        msgbuf_t * msgbuf, bool queue)
{
    assert(connection);
    assert(address);
    /* msgbuf can be NULL */

    connection_udp_data_t * data = connection->data;
    assert(data);

    /* Flush if required or if queue is full */
    if ((!msgbuf) || (queue && (data->queue_len > MAX_MSG)))  {
        /* Flush operation */
#ifdef WITH_ZEROCOPY
        int flags = MSG_ZEROCOPY;
#else
        int flags = 0;
#endif /* WITH_ZEROCOPY */
        int n = sendmmsg(connection->fd, data->msgbufs, data->queue_len, flags);
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
        struct iovec *iovec = &data->iovecs[data->queue_len++];
        iovec->iov_base = msgbuf_packet(msgbuf);
        iovec->iov_len = msgbuf_len(msgbuf);

    } else {
        ssize_t writeLength = write(connection->fd, msgbuf_packet(msgbuf), msgbuf_len(msgbuf));

        if (writeLength < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return false;
            } else {
                // this print is for debugging
                printf("Incorrect write length %zd, expected %u: (%d) %s\n", writeLength,
                        msgbuf_len(msgbuf), errno, strerror(errno));
                return false;
            }
        }
    }

    return true;
}

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

static
void
connection_udp_send_packet(const connection_t * connection, const uint8_t * packet)
{
    assert(ops);
    assert(packet);

    if(connection_local(connection))
        return;

    ssize_t n = sendto(connection, packet,
            messageHandler_GetTotalPacketLength(message), 0,
            address_sa(address_pair_remote(&udp->pair)),
            address_socklen(address_pair_remote(&udp->pair)));
    if (n < 0)
        return;
}

DECLARE_CONNECTION(udp);
