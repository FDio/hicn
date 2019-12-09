/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

/* This has to be included early as other modules are including socket.h */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <errno.h>

#include <hicn/processor/messageProcessor.h>
#include <hicn/base/msgbuf.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <hicn/hicn-light/config.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#ifdef WITH_GSO
#include <netinet/if_ether.h> // ETH_DATA_LEN
#include <linux/ipv6.h> // struct ipv6hdr
#include <netinet/udp.h> // struct udphdr, SOL_UDP
//#include <linux/udp.h> // UDP_GRO
#define UDP_GRO 104
#endif /* WITH_GSO */

#include <hicn/core/messageHandler.h>

#include <hicn/io/udpConnection.h>
#include <hicn/io/udpListener.h>

#include <parc/algol/parc_Network.h>
#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/core/connection.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/messagePacketType.h>

#define IPv4 4
#define IPv6 6

#define DEBUG(FMT, ...) do {                                                    \
    if (logger_IsLoggable(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug))  \
      logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,  \
                 FMT, ## __VA_ARGS__);                                          \
} while(0);

#define ERROR(FMT, ...) do {                                                    \
    if (logger_IsLoggable(udp->logger, LoggerFacility_IO,  PARCLogLevel_Error)) \
      logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Error, __func__,  \
                 FMT, ## __VA_ARGS__);                                          \
} while(0);

struct udp_listener {
  char *listenerName;
  Forwarder *forwarder;
  Logger *logger;

  PARCEvent *udp_event;
  SocketType udp_socket;
  uint16_t port;

  unsigned id;
  char *interfaceName;
  struct sockaddr_storage local_addr;

  /* recvmmsg data structures */
  struct mmsghdr msghdr[MAX_MSG]; // XXX = {0};
  char buffers[MAX_MSG][MTU_SIZE];
  struct iovec iovecs[MAX_MSG]; // XXX = {0};
  struct sockaddr_storage addrs[MAX_MSG];
  msgbuf_t messages[MAX_MSG];
  Connection * messages_conn[MAX_MSG];

  uint8_t * commands[MAX_MSG];
  unsigned commands_connid[MAX_MSG];

};

static void _destroy(ListenerOps **listenerOpsPtr);
static const char *_getListenerName(const ListenerOps *listener);
static unsigned _getInterfaceIndex(const ListenerOps *listener);
static const address_t * _getListenAddress(const ListenerOps *listener);
static EncapType _getEncapType(const ListenerOps *listener);
static const char *_getInterfaceName(const ListenerOps *ops);
static int _getSocket(const ListenerOps *listener, const address_pair_t * pair);

static unsigned _createNewConnection(ListenerOps *listener, int fd, const address_pair_t *pair);

static ListenerOps udpTemplate = {
  .context = NULL,
  .destroy = &_destroy,
  .getInterfaceIndex = &_getInterfaceIndex,
  .getListenAddress = &_getListenAddress,
  .getEncapType = &_getEncapType,
  .getSocket = &_getSocket,
  .getListenerName = &_getListenerName,
  .createConnection = &_createNewConnection,
  .getInterfaceName = &_getInterfaceName,
};


static void _readcb(int fd, PARCEventType what, void * listener_void);

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

#ifdef __ANDROID__
extern int bindSocket(int sock, const char* ifname);
#endif

/******************************************************************************
 * Helpers
 ******************************************************************************/

int
init_batch_buffers(UdpListener * udp)
{
  /* Setup recvmmsg data structures. */
  for (unsigned i = 0; i < MAX_MSG; i++) {
    char *buf = &udp->buffers[i][0];
    struct iovec *iovec = &udp->iovecs[i];
    struct mmsghdr *msg = &udp->msghdr[i];

    msg->msg_hdr.msg_iov = iovec;
    msg->msg_hdr.msg_iovlen = 1;

    msg->msg_hdr.msg_name = &udp->addrs[i];
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

void
socket_close(int fd)
{
#ifndef _WIN32
  close(fd);
#else
  closesocket(fd);
#endif
}

// TODO with address
int
make_socket(const address_t * local, const address_t * remote, const char * interfaceName)
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
  socket_close(fd);
ERR_SOCKET:
  return -1;
}

/******************************************************************************/

ListenerOps *
udpListener_Create(Forwarder *forwarder, char *listenerName,
        const address_t * address, const char *interfaceName)
{

//        int family, struct sockaddr * sa, socklen_t sl,

  ListenerOps *listener = NULL;

  UdpListener *udp = parcMemory_AllocateAndClear(sizeof(UdpListener));
  if (!udp) {
    ERROR("parcMemory_AllocateAndClear(%zu) returned NULL", sizeof(UdpListener));
    goto ERR_UDP;
  }
  udp->forwarder = forwarder;
  udp->listenerName = parcMemory_StringDuplicate(listenerName, strlen(listenerName));
  udp->interfaceName = parcMemory_StringDuplicate(interfaceName, strlen(interfaceName));
  udp->logger = logger_Acquire(forwarder_GetLogger(forwarder));
  udp->local_addr = *address;
  udp->id = forwarder_GetNextConnectionId(forwarder);

  init_batch_buffers(udp);

  udp->udp_socket = make_socket(address, NULL, interfaceName);
  if (udp->udp_socket < 0) {
    ERROR("Error creating UDP socket: (%d) %s", errno, strerror(errno));
    goto ERR_SOCKET;
  }

  listener = parcMemory_AllocateAndClear(sizeof(ListenerOps));
  if (!listener) {
    ERROR("parcMemory_AllocateAndClear(%zu) returned NULL",
            sizeof(ListenerOps));
    goto ERR;
  }
  memcpy(listener, &udpTemplate, sizeof(ListenerOps));
  listener->context = udp;

  udp->udp_event = dispatcher_CreateNetworkEvent(
          forwarder_GetDispatcher(forwarder), true, _readcb, (void*)listener,
          udp->udp_socket);
  dispatcher_StartNetworkEvent(forwarder_GetDispatcher(forwarder),
          udp->udp_event);

// XXX TODO
#if 0
  char *str = addressToString(udp->local_addr);
  DEBUG("UdpListener %p created for address %s", (void *)udp, str);
  parcMemory_Deallocate((void **)&str);
#endif

  return listener;

ERR:
  socket_close(udp->udp_socket);
ERR_SOCKET:
  logger_Release(&udp->logger);
  parcMemory_Deallocate((void **)&udp->interfaceName);
  parcMemory_Deallocate((void **)&udp->listenerName);
  parcMemory_Deallocate((void **)&udp);
ERR_UDP:
  return NULL;

}

static void udpListener_Destroy(UdpListener **listenerPtr) {
  parcAssertNotNull(listenerPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*listenerPtr,
                    "Parameter must derefernce to non-null pointer");

  UdpListener *udp = *listenerPtr;

  DEBUG("UdpListener %p destroyed", (void *)udp);

  parcMemory_Deallocate((void **)&udp->listenerName);
  parcMemory_Deallocate((void **)&udp->interfaceName);
#ifndef _WIN32
  close(udp->udp_socket);
#else
  closesocket(udp->udp_socket);
#endif

  dispatcher_DestroyNetworkEvent(forwarder_GetDispatcher(udp->forwarder),
                                 &udp->udp_event);
  logger_Release(&udp->logger);
  parcMemory_Deallocate((void **)&udp);
  *listenerPtr = NULL;
}

static const char *_getListenerName(const ListenerOps *ops) {
  UdpListener *udp = (UdpListener *)ops->context;
  return udp->listenerName;
}

static const char *_getInterfaceName(const ListenerOps *ops) {
  UdpListener *udp = (UdpListener *)ops->context;
  return udp->interfaceName;
}

static void _destroy(ListenerOps **listenerOpsPtr) {
  ListenerOps *listener = *listenerOpsPtr;
  UdpListener *udp = (UdpListener *)listener->context;
  udpListener_Destroy(&udp);
  parcMemory_Deallocate((void **)&listener);
  *listenerOpsPtr = NULL;
}

static unsigned _getInterfaceIndex(const ListenerOps *listener) {
  UdpListener *udp = (UdpListener *)listener->context;
  return udp->id;
}

static
const address_t *
_getListenAddress(const ListenerOps *listener) {
  UdpListener *udp = (UdpListener *)listener->context;
  return &udp->local_addr;
}

static EncapType _getEncapType(const ListenerOps *ops) { return ENCAP_UDP; }

static
int
_getSocket(const ListenerOps *listener, const address_pair_t * pair)
{
  UdpListener *udp = (UdpListener *)listener->context;

  int fd = make_socket(&pair->local, &pair->remote, udp->interfaceName);
  if (fd < 0) {
    ERROR("Error creating socket");
    goto ERR_SOCKET;
  }

  /* A new socket was created, register it to the event loop */
  PARCEvent *udp_event = dispatcher_CreateNetworkEvent(
          forwarder_GetDispatcher(udp->forwarder), true, _readcb,
          (void *)listener, fd);
  dispatcher_StartNetworkEvent(forwarder_GetDispatcher(udp->forwarder),
          udp_event);

  return fd;

ERR_SOCKET:
  ERROR("Failed to create connected socket, falling back to common socket");
  return (int)udp->udp_socket;
}

// =====================================================================


/**
 * @function _createNewConnection
 * @abstract Creates a new Metis connection for the peer
 * @discussion
 *   PRECONDITION: you know there's not an existing connection with the address
 * pair
 *
 *   Creates a new connection and adds it to the connection table.
 *
 * @param <#param1#>
 * @return The connection id for the new connection
 */

static unsigned _createNewConnection(ListenerOps * listener, int fd,
                                     const address_pair_t * pair)
{
  UdpListener * udp = (UdpListener *)listener->context;

  bool isLocal = address_is_local(address_pair_local(pair));
  connection_table_t * table = forwarder_GetConnectionTable(udp->forwarder);
  Connection ** conn_ptr;
  connection_table_allocate(table, conn_ptr, pair);

  unsigned connid = connection_table_get_connection_id(table, conn_ptr);

  IoOperations *ioops = udpConnection_Create(udp->forwarder, udp->interfaceName, fd, pair, isLocal, connid);
  *conn_ptr = connection_Create(ioops);
  // connection_AllowWldrAutoStart(conn);

  return connid;
}

static void _readcb(int fd, PARCEventType what, void * listener_void)
{
  ListenerOps * listener = (ListenerOps *)listener_void;
  UdpListener * udp = (UdpListener *)listener->context;

  DEBUG("%s socket %d what %s%s%s%s data %p", __func__, fd,
          (what & PARCEventType_Timeout) ? " timeout" : "",
          (what & PARCEventType_Read) ? " read" : "",
          (what & PARCEventType_Write) ? " write" : "",
          (what & PARCEventType_Signal) ? " signal" : "", udp);

  if (!(what & PARCEventType_Read))
    return;

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

    msgbuf_from_packet(&udp->messages[valid], packet, pktType, connid,
            forwarder_GetTicks(udp->forwarder),
            forwarder_GetLogger(udp->forwarder));
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
