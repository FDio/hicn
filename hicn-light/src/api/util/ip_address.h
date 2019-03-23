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
 * Parse ip addresses in presentation format, or prefixes (in bits, separated by a slash)
 */
static inline
int
ip_address_pton (const char *ip_address_str, ip_address_t * ip_address)
{
  int pton_fd;
#ifdef IP_ADDRESS_PREFIX
  char *p;
  char *eptr;
  u32 dst_len;
#endif /* IP_ADDRESS_PREFIX */
  char *addr = strdup (ip_address_str);
  int family;

#ifdef IP_ADDRESS_PREFIX
  p = strchr (addr, '/');
  if (!p)
    {
      dst_len = 0;		// until we get the ip address family
    }
  else
    {
      dst_len = strtoul (p + 1, &eptr, 10);
      *p = 0;
    }
#endif /* IP_ADDRESS_PREFIX */

  family = ip_address_get_family (addr);

  switch (family)
    {
    case AF_INET6:
#ifdef IP_ADDRESS_PREFIX
      if (dst_len > IPV6_ADDR_LEN_BITS)
	goto ERR;
#endif /* IP_ADDRESS_PREFIX */
      pton_fd = inet_pton (AF_INET6, addr, &ip_address->buffer);
      break;
    case AF_INET:
#ifdef IP_ADDRESS_PREFIX
      if (dst_len > IPV4_ADDR_LEN_BITS)
	goto ERR;
#endif /* IP_ADDRESS_PREFIX */
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

#endif /* UTIL_IP_ADDRESS_H */
