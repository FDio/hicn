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

/**
 * \file ip_address.h
 * \brief IP address type support
 */
#ifndef UTIL_IP_ADDRESS_H
#define UTIL_IP_ADDRESS_H

#include <arpa/inet.h>  // inet_ntop
#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define __bswap_constant_32(x) OSSwapInt32(x)
#include <machine/endian.h>
#else
#include <endian.h>
#endif
#include <errno.h>
#include <netdb.h> // struct addrinfo
#include <netinet/in.h> // INET*_ADDRSTRLEN, IN*ADDR_LOOPBACK
#include <stdlib.h>
#include <stdio.h> // snprintf
#include <string.h> // memset

#include "types.h"

#define bytes_to_bits(x) (x * 8)
#define IPV6_ADDR_LEN 16	/* bytes */
#define IPV4_ADDR_LEN 4		/* bytes */
#define IPV6_ADDR_LEN_BITS bytes_to_bits(IPV6_ADDR_LEN)
#define IPV4_ADDR_LEN_BITS bytes_to_bits(IPV4_ADDR_LEN)

#define IP_MAX_ADDR_LEN IPV6_ADDR_LEN

#define DUMMY_PORT 1234

typedef union {
    union {
        struct in_addr as_inaddr;
        u8 as_u8[4];
        u16 as_u16[2];
        u32 as_u32;
    } v4;
    union {
        struct in6_addr as_in6addr;
        u8 as_u8[16];
        u16 as_u16[8];
        u32 as_u32[4];
        u64 as_u64[2];
    } v6;
    u8 buffer[IP_MAX_ADDR_LEN];
    u8 as_u8[IP_MAX_ADDR_LEN];
    u16 as_u16[IP_MAX_ADDR_LEN >> 1];
    u32 as_u32[IP_MAX_ADDR_LEN >> 2];
    u64 as_u64[IP_MAX_ADDR_LEN >> 3];
} ip_address_t;

#define MAXSZ_IP4_ADDRESS_ INET_ADDRSTRLEN - 1
#define MAXSZ_IP6_ADDRESS_ INET6_ADDRSTRLEN - 1
#define MAXSZ_IP_ADDRESS_ MAXSZ_IP6_ADDRESS_
#define MAXSZ_IP4_ADDRESS MAXSZ_IP4_ADDRESS_ + 1
#define MAXSZ_IP6_ADDRESS MAXSZ_IP6_ADDRESS_ + 1
#define MAXSZ_IP_ADDRESS MAXSZ_IP_ADDRESS_ + 1

typedef struct {
  int family;
  ip_address_t address;
  u8 len;
} ip_prefix_t;

#define MAXSZ_PREFIX_ MAXSZ_IP_ADDRESS_ + 1 + 3
#define MAXSZ_PREFIX MAXSZ_PREFIX_ + 1

/* No htonl() with const */
static const ip_address_t IPV4_LOOPBACK = {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    .v4.as_inaddr.s_addr = __bswap_constant_32(INADDR_LOOPBACK),
#else
    .v4.as_inaddr.s_addr = INADDR_LOOPBACK,
#endif
};

static const ip_address_t IPV6_LOOPBACK = {
    .v6.as_in6addr = IN6ADDR_LOOPBACK_INIT,
};

static const ip_address_t IPV4_ANY = {
    .v4.as_inaddr.s_addr = INADDR_ANY,
};

static const ip_address_t IPV6_ANY = {
    .v6.as_in6addr = IN6ADDR_ANY_INIT,
};

#define IP_ANY(family) (family == AF_INET) ? IPV4_ANY : IPV6_ANY

static const ip_address_t IP_ADDRESS_EMPTY = {
    .as_u64 = { 0 },
};


#define MAX_PORT 1 << (8 * sizeof(u16))
#define IS_VALID_PORT(x) ((x > 0) && (x < MAX_PORT))

#define MAXSZ_PORT_ 5
#define MAXSZ_PORT MAXSZ_PORT_ + 1

#define IS_VALID_FAMILY(x) ((x == AF_INET) || (x == AF_INET6))

static inline
int
ip_address_get_family (const char * ip_address)
{
  struct addrinfo hint, *res = NULL;
  int rc;

  memset (&hint, '\0', sizeof hint);

  hint.ai_family = PF_UNSPEC;
  hint.ai_flags = AI_NUMERICHOST;

  rc = getaddrinfo (ip_address, NULL, &hint, &res);
  if (rc)
    {
      return -1;
    }
  rc = res->ai_family;
  freeaddrinfo (res);
  return rc;
}

static inline
int
ip_address_len (const ip_address_t * ip_address, int family)
{
  return (family == AF_INET6) ? IPV6_ADDR_LEN :
    (family == AF_INET) ? IPV4_ADDR_LEN : 0;
}

static inline
int
ip_address_ntop (const ip_address_t * ip_address, char *dst, const size_t len,
		int family)
{
  const char * s = inet_ntop (family, ip_address->buffer, dst, len);
  return (s ? 1 : -1);
}

/*
 * Parse ip addresses in presentation format
 */
static inline
int
ip_address_pton (const char *ip_address_str, ip_address_t * ip_address)
{
  int pton_fd;
  char *addr = strdup (ip_address_str);
  int family;


  family = ip_address_get_family (addr);

  switch (family)
    {
    case AF_INET6:
      pton_fd = inet_pton (AF_INET6, addr, &ip_address->buffer);
      break;
    case AF_INET:
      pton_fd = inet_pton (AF_INET, addr, &ip_address->buffer);
      break;
    default:
      goto ERR;
    }

  //   0 = not in presentation format
  // < 0 = other error (use perror)
  if (pton_fd <= 0)
    {
      goto ERR;
    }

  return 1;
ERR:
  free (addr);
  return -1;
}



static inline
int
ip_address_snprintf(char * s, size_t size, const ip_address_t * ip_address, int family)
{
    size_t len = family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
    const char * rc = inet_ntop (family, ip_address->buffer, s, len);
    return rc ? strlen(rc) : -1;
}


static inline
int
ip_address_to_sockaddr(const ip_address_t * ip_address,
		struct sockaddr *sockaddr_address, int family)
{
  struct sockaddr_in6 *tmp6 = (struct sockaddr_in6 *) sockaddr_address;
  struct sockaddr_in *tmp4 = (struct sockaddr_in *) sockaddr_address;

  switch (family)
    {
    case AF_INET6:
      tmp6->sin6_family = AF_INET6;
      tmp6->sin6_port = DUMMY_PORT;
      tmp6->sin6_scope_id = 0;
      memcpy (&tmp6->sin6_addr, ip_address->buffer, IPV6_ADDR_LEN);
      break;
    case AF_INET:
      tmp4->sin_family = AF_INET;
      tmp4->sin_port = DUMMY_PORT;
      memcpy (&tmp4->sin_addr, ip_address->buffer, IPV4_ADDR_LEN);
      break;
    default:
      return -1;
    }

  return 1;
}

static inline
int
ip_address_cmp(const ip_address_t * ip1, const ip_address_t * ip2, int family)
{
    return memcmp(ip1, ip2, ip_address_len(ip1, family));
}

static inline
int
ip_address_empty(const ip_address_t * ip)
{
    return (memcmp(ip, &IP_ADDRESS_EMPTY, sizeof(IP_ADDRESS_EMPTY)) == 0);
}

/* Parse IP Prefixes in presentation format (in bits, separated by a slash) */
static inline
int
ip_prefix_pton (const char *ip_address_str, ip_prefix_t * ip_prefix)
{
  int pton_fd;
  char *p;
  char *eptr;
  char *addr = strdup (ip_address_str);

  p = strchr (addr, '/');
  if (!p)
    {
      ip_prefix->len = 0;		// until we get the ip address family
    }
  else
    {
      ip_prefix->len = strtoul (p + 1, &eptr, 10);
      *p = 0;
    }

  ip_prefix->family = ip_address_get_family (addr);

  switch (ip_prefix->family)
    {
    case AF_INET6:
      if (ip_prefix->len > IPV6_ADDR_LEN_BITS)
	goto ERR;
      pton_fd = inet_pton (AF_INET6, addr, &ip_prefix->address.buffer);
      break;
    case AF_INET:
      if (ip_prefix->len > IPV4_ADDR_LEN_BITS)
	goto ERR;
      pton_fd = inet_pton (AF_INET, addr, &ip_prefix->address.buffer);
      break;
    default:
      goto ERR;
    }

  //   0 = not in presentation format
  // < 0 = other error (use perror)
  if (pton_fd <= 0)
    {
      goto ERR;
    }

  return 1;
ERR:
  free (addr);
  return -1;
}

static inline
int
ip_prefix_ntop (const ip_prefix_t * ip_prefix, char *dst, size_t size)
{
  char ip_s[MAXSZ_IP_ADDRESS];
  const char * s = inet_ntop (ip_prefix->family, ip_prefix->address.buffer, ip_s, MAXSZ_IP_ADDRESS);
  if (!s)
      return -1;
  size_t n = snprintf(dst, size, "%s/%d", ip_s, ip_prefix->len);

  return (n > 0 ? 1 : -1);
}


#endif /* UTIL_IP_ADDRESS_H */
