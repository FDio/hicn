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

#ifndef TRANSPORT_INTERFACES_C_API
#define TRANSPORT_INTERFACES_C_API

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef unsigned short int hicn_sa_family_t;

#define TRANSPORT_SOCKADDR_COMMON(sa_prefix) hicn_sa_family_t sa_prefix##family

#define TRANSPORT_SOCKADDR_COMMON_SIZE (sizeof(unsigned short int))

/**
 * Size of struct hicn_sockaddr_storage.
 */
#define TRANSPORT_SS_SIZE 128

struct hicn_sockaddr {
  TRANSPORT_SOCKADDR_COMMON(sa_); /* Common data: address family and length.  */
  char sa_data[14];               /* Address data.  */
};

/**
 * Structure large enough to hold any socket address.
 */
#define ss_aligntype unsigned long int
#define TRANSPORT_SS_PADSIZE \
  (TRANSPORT_SS_SIZE - TRANSPORT_SOCKADDR_COMMON_SIZE - sizeof(ss_aligntype))

struct hicn_sockaddr_storage {
  TRANSPORT_SOCKADDR_COMMON(ss_); /* Address family, etc.  */
  char __ss_padding[TRANSPORT_SS_PADSIZE];
  ss_aligntype __ss_align; /* Force desired alignment.  */
};

/* Bits in the FLAGS argument to `send', `recv', et al.  */
enum {
  MSG_OOB = 0x01, /* Process out-of-band data.  */
#define MSG_OOB MSG_OOB
  MSG_PEEK = 0x02, /* Peek at incoming messages.  */
#define MSG_PEEK MSG_PEEK
  MSG_DONTROUTE = 0x04, /* Don't use local routing.  */
#define MSG_DONTROUTE MSG_DONTROUTE
  MSG_CTRUNC = 0x08, /* Control data lost before delivery.  */
#define MSG_CTRUNC MSG_CTRUNC
  MSG_PROXY = 0x10, /* Supply or ask second address.  */
#define MSG_PROXY MSG_PROXY
  MSG_TRUNC = 0x20,
#define MSG_TRUNC MSG_TRUNC
  MSG_DONTWAIT = 0x40, /* Nonblocking IO.  */
#define MSG_DONTWAIT MSG_DONTWAIT
  MSG_EOR = 0x80, /* End of record.  */
#define MSG_EOR MSG_EOR
  MSG_WAITALL = 0x100, /* Wait for a full request.  */
#define MSG_WAITALL MSG_WAITALL
  MSG_FIN = 0x200,
#define MSG_FIN MSG_FIN
  MSG_SYN = 0x400,
#define MSG_SYN MSG_SYN
  MSG_CONFIRM = 0x800, /* Confirm path validity.  */
#define MSG_CONFIRM MSG_CONFIRM
  MSG_RST = 0x1000,
#define MSG_RST MSG_RST
  MSG_ERRQUEUE = 0x2000, /* Fetch message from error queue.  */
#define MSG_ERRQUEUE MSG_ERRQUEUE
  MSG_NOSIGNAL = 0x4000, /* Do not generate SIGPIPE.  */
#define MSG_NOSIGNAL MSG_NOSIGNAL
  MSG_MORE = 0x8000, /* Sender will send more.  */
#define MSG_MORE MSG_MORE
  MSG_WAITFORONE = 0x10000, /* Wait for at least one packet to return.*/
#define MSG_WAITFORONE MSG_WAITFORONE
  MSG_BATCH = 0x40000, /* sendmmsg: more messages coming.  */
#define MSG_BATCH MSG_BATCH
  MSG_ZEROCOPY = 0x4000000, /* Use user data in kernel path.  */
#define MSG_ZEROCOPY MSG_ZEROCOPY
  MSG_FASTOPEN = 0x20000000, /* Send data in TCP SYN.  */
#define MSG_FASTOPEN MSG_FASTOPEN
  MSG_CMSG_CLOEXEC = 0x40000000 /* Set close_on_exit for file
                                   descriptor received through
                                   SCM_RIGHTS.  */
#define MSG_CMSG_CLOEXEC MSG_CMSG_CLOEXEC
};

/**
 * Type to represent a socklen_t
 */
typedef uint32_t hicn_socklen_t;

/* Type to represent a port.  */
typedef uint16_t hicn_in_port_t;

/* Structure describing messages sent by
   `sendmsg' and received by `recvmsg'.  */
struct hicn_msghdr {
  void *msg_name;             /* Address to send to/receive from.  */
  hicn_socklen_t msg_namelen; /* Length of address data.  */

  struct iovec *msg_iov; /* Vector of data to send/receive into.  */
  size_t msg_iovlen;     /* Number of elements in the vector.  */

  void *msg_control;     /* Ancillary data (eg BSD filedesc passing). */
  size_t msg_controllen; /* Ancillary data buffer length.
                             !! The type should be socklen_t but the
                             definition of the kernel is incompatible
                             with this.  */

  int msg_flags; /* Flags on received message.  */
};

/**
 * IPV4 address
 */
struct hicn_in_addr {
  uint32_t addr;
};

/**
 * IPv6 address
 */
typedef struct hicn_in6_addr {
  union {
    uint8_t addr8[16];
    uint16_t addr16[8];
    uint32_t addr32[4];
  } u6_addr; /* 128-bit IP6 address */
} in6_addr_t;

struct hicn_sockaddr_in {
  TRANSPORT_SOCKADDR_COMMON(sin_);
  hicn_socklen_t sin_port;      /* Port number.  */
  struct hicn_in_addr sin_addr; /* Internet address.  */

  /* Pad to size of `struct sockaddr'.  */
  unsigned char sin_zero[sizeof(struct hicn_sockaddr) -
                         TRANSPORT_SOCKADDR_COMMON_SIZE -
                         sizeof(hicn_in_port_t) - sizeof(struct hicn_in_addr)];
};

struct hicn_sockaddr_in6 {
  TRANSPORT_SOCKADDR_COMMON(sin6_);
  hicn_in_port_t sin6_port;       /* Transport layer port # */
  uint32_t sin6_flowinfo;         /* IPv6 flow information */
  struct hicn_in6_addr sin6_addr; /* IPv6 address */
  uint32_t sin6_scope_id;         /* IPv6 scope-id */
};

#define TRANSPORT_SOCKADDR_ARG struct hicn_sockaddr *__restrict
#define TRANSPORT_CONST_SOCKADDR_ARG const struct hicn_sockaddr *

enum socket_domains {
  AF_HICN,
};

enum socket_types {
  SOCK_PROD,
  SOCK_CONS,
};

enum socket_protocols { PROD_REL, PROD_UNREL, CONS_REL, CONS_CBR, CONS_RTC };

/**
 * Create a new socket of type type using the supplied protocol.
 * The domain is always AF_HICN.
 *
 * @param domain - The socket domain. The only option available is AF_HICN.
 * @param type - The socket type. 2 types are currently available: SOCK_PROD and
 * SOCK_CONS
 * @param protocol - The protocol to be used for the socket type selected.
 *
 * return An opaque integer referencing the socket created.
 */
extern int hicn_socket(int domain, int type, int protocol);

/**
 * Assign to the socket `socket` the address `address` of length `len`.
 *
 * @param socket - The integer representing the socket.
 * @param address - A pointer to the struct sockaddr* containing the address.
 * @param len - The length of the struct sockaddr.
 */
extern int hicn_bind(int socket, TRANSPORT_CONST_SOCKADDR_ARG address,
                     hicn_socklen_t len);

/**
 * Set the max number of queued interest, on a socket of type SOCK_PROD.
 *
 * @param socket - The integer representing the producer socket.
 * @param n - The maximum number of interest to store in the input queue before
 * starting to drop them.
 *
 * @return 0 on success, < 0 on errors
 */
extern int hicn_listen(int socket, int n);

/**
 * Register the name to use for retrieving/publishing a content when using
 * read/recv/write/send calls. It is worth reminding that hicn socket are
 * connectionless by default, then this system call NEVER connect to a remote
 * endpoint, as it would do with a TCP socket.
 *
 * @param socket - The integer representing the hicn socket.
 * @param address - The address to associate to the socket, to be used for
 * retrieving/publishinc a conetnt in a subsequent read/recv/write/send.
 * @param len - Pointer to the length of the address struct.
 *
 * @return 0 on success, < 0 on errors
 */
extern int hicn_connect(int socket, TRANSPORT_CONST_SOCKADDR_ARG address,
                        hicn_socklen_t *__restrict len);

/**
 * The accept API is not implemented.
 *
 */
// extern int accept(int socket, TRANSPORT_SOCKADDR_ARG address, hicn_socklen_t
// *__restrict len);

/**
 * Send `length` bytes of `buff` into socket, and use the name specified in
 * the last call to connect().
 *
 * @param socket - The integer representing the hicn producer socket.
 * @param buff - Pointer to the first byte of the buffer to send
 * @param length - Length of the buffer
 * @param flags - Flags to set for the production
 *
 * @return The number of sent bytes or < 0 if error occurred.
 */
extern int hicn_send(int socket, const void *buff, size_t length, int flags);

/**
 * Receive a max of length bytes into buffer buff.
 *
 * @param socket - The integer representing the hicn consumer socket.
 * @param buff - Pointer to the first byte of the buffer used for storing the
 * received bytes.
 * @param length - The max number of bytes to read.
 * @param flags - Flags to pass to the consumer socket.
 *
 * @return The number of bytes read, which could be less than the number of
 * bytes specified in the length parameter.
 *
 * @return The number of received bytes or < 0 if error occurred.
 */
extern int hicn_recv(int socket, void *buff, size_t length, int flags);

/**
 * Send `length` bytes of `buff` into socket, using the name specified in
 * `address`.
 *
 * @param socket - The integer representing the producer socket.
 * @param buff - The buffer to produce
 * @param length - The length of the buffer to produce
 * @param flags - The flags associated to this production
 * @param address - The struct hicn_addr storing the name to use for publishing
 * this buffer.
 * @param addr_len - The length of the address struct'
 *
 * @return The number of sent bytes or < 0 if error occurred.
 */
extern int hicn_sendto(int socket, const void *buff, size_t length, int flags,
                       TRANSPORT_CONST_SOCKADDR_ARG address,
                       hicn_socklen_t addr_len);

/**
 * Read a max of length bytes from socket `socket`. The name of the content ot
 * read is stored int he address structure, which has length len. Optionally
 * pass some flags.
 *
 * @param socket - The integer representing the consumer socket.
 * @param buff - The buffer where the content will be stored
 * @param length - The max number of bytes to store in buff
 * @param flags - Optional flags to be passed for this read operation
 * @param address - The struct hicn_addr storing the name to be used for
 * retrieving the content.
 * @param len - The length of the struct hicn_addr struct.
 *
 * @return The number of received bytes or < 0 if error occurred.
 */
extern int hicn_recvfrom(int socket, void *buff, size_t length, int flags,
                         TRANSPORT_SOCKADDR_ARG address,
                         hicn_socklen_t *__restrict len);

/**
 * Send an interest in a datagram fashion using the supplied socket, which has
 * to be a consumer socket.
 *
 * @param socket - The integer representing the consumer socket.
 * @param message - The struct hicn_msghdr containing the name for the interest,
 * an optional payload, and message flags. The control part (msg_control and
 * msg_controllen) are not used.
 * @param flags - Flags associated to this operation.
 *
 * @return The number of sent bytes or < 0 if error occurred.
 */
extern int hicn_sendmsg(int socket, const struct hicn_msghdr *message,
                        int flags);

/**
 * Receive an interest in a datagram fashion using the supplied socket, which
 * hash to be a producer socket.
 *
 * @param socket - The integer representing the producer socket.
 * @param message - The hicn_msghdr which will be filled with the interest
 * payload, the interest name and eventually flags.
 * @param flags - Flags associated to this operation.
 *
 * @return The number of bytes received or < 0 if error occurred.
 */
extern int hicn_recvmsg(int socket, struct hicn_msghdr *message, int flags);

/**
 * Shutdown the socket. Note that since there is no concept of connection this
 * operation just shutdown the socket passed as parameters, not the other parts.
 *
 * @param socket - The integer representing the socket.
 * @param how - Not used.
 *
 * @return 0 on success, < 0 on error.
 */
extern int hicn_shutdown(int socket, int how);

/**
 * Same behavior os shutdown.
 */
extern int hicn_close(int socket, int how);

/**
 * Put the current value for socket's option `optname` at protocol level `level`
 * into optval (which is *optlen bytes long), and set *optlen to the value's
 * actual length.
 *
 * @param socket - The integer representing the socket.
 * @param level - Not used
 * @param optname - The key identifying the option to get
 * @param optval - The pointer to the socket option value.
 * @param optlen - The length of the option value.
 *
 * @return 0 on success, < 0 on error.
 */
extern int hicn_getsockopt(int socket, int level, int optname,
                           void *__restrict optval,
                           hicn_socklen_t *__restrict optlen);

/**
 * Set socket FD's option OPTNAME at protocol level LEVEL
 * to *OPTVAL (which is OPTLEN bytes long).
 *
 * @param socket - The integer representing the socket.
 * @param level - Not used
 * @param optname - The key identifying the socket option value
 * @param optval - The pointer to the value to set
 * @param optlen - The size of the option value to set.
 *
 * @returns 0 on success, < 0 for errors.
 */
extern int hicn_setsockopt(int socket, int level, int optname,
                           const void *optval, hicn_socklen_t optlen);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif