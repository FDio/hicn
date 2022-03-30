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
 * @file common.c
 * @brief Common interfaces abstracting low-level platform.
 * details.
 *
 * The role of this header file is to provide an uniform interface to the
 * different platform on top of which we build the hICN interface:
 *  - syntax helpers
 *  - IP address management
 *  - protocol definition
 *  - ...
 *
 * The rationale is to leverage as much as possible platform-specific code,
 * however some level of harmonization is needed to build code on top. Whenever
 * possible, we align to VPP structure and naming.
 */

#ifndef HICN_COMMON_H
#define HICN_COMMON_H

#include <stdint.h>
#include <assert.h>

/* Concise type definitions */

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

/*
 * Code annotations
 *
 * NOTE: these are defined by default in VPP.
 */

#ifndef HICN_VPP_PLUGIN

#define PREDICT_FALSE(x)	     (x)
#define PREDICT_TRUE(x)		     (x)
#define STRUCT_SIZE_OF(type, member) sizeof (((type *) 0)->member)
#define ASSERT

#ifndef NDEBUG
#define _ASSERT(x) assert (x)
#else
#define _ASSERT(x) ((void) (x))
#endif

#define STATIC_ASSERT(x)

/* Architecture-dependent uword size */
#if INTPTR_MAX == INT64_MAX
#define log2_uword_bits 6
#elif INTPTR_MAX == INT32_MAX
#define log2_uword_bits 5
#else
#error "Impossible to detect architecture"
#endif

#define uword_bits (1 << log2_uword_bits)

/* Word types. */
#if uword_bits == 64
/* 64 bit word machines. */
typedef u64 uword;
#else
/* 32 bit word machines. */
typedef u32 uword;
#endif

typedef uword ip_csum_t;

#else

#include <vppinfra/clib.h>

#endif /* ! HICN_VPP_PLUGIN */

/*
 * Windows compilers do not support named initilizers when .h files are
 * included inside C++ files. For readability, we either use the following
 * macro, or duplicate some code, with the intent of preserving those
 * safeguards for non-Windows platforms.
 */
#ifndef _WIN32
#define ATTR_INIT(key, value) .key = value
#else
#define ATTR_INIT(key, value) value
#endif

#ifdef _WIN32
/* Endianness detection for Windows platforms */
#define __ORDER_LITTLE_ENDIAN__ 0x41424344UL
#define __ORDER_BIG_ENDIAN__	0x44434241UL
#define __BYTE_ORDER__		('ABCD')

/* Windows compatibility headers */
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <Ws2tcpip.h>
#include <In6addr.h>

#define strdup _strdup
#define __attribute__(A)

#ifndef IOVEC
#define IOVEC
#define UIO_MAXIOV 16
#define IOV_MAX	   UIO_MAXIOV
struct iovec
{
  void *iov_base;
  size_t iov_len;
};
#endif
#endif

/*
 * Portable attribute packed.
 */
#ifndef _WIN32
#define PACKED(__Declaration__) __Declaration__ __attribute__ ((__packed__))
#else
#define PACKED(__Declaration__)                                               \
  __pragma (pack (push, 1)) __Declaration__ __pragma (pack (pop))
#endif

/*
 * IP address types
 */

#ifndef _WIN32
#include <netinet/in.h>
#endif

/**
 * @brief Returns the family of an IP address
 * @param [in] ip_address - IP address in presentation format
 * @return AF_INET or AF_INET6 if successful, -1 otherwise
 */
int get_addr_family (const char *ip_address);

/*
 * Checksum computation
 *
 * NOTE: VPP provides efficient (incremental) checksum computations
 * that we reuse, and provide alternative implementation otherwise.
 */

#ifndef HICN_VPP_PLUGIN

/*
 * Checksum update (incremental and non-incremental)
 *
 * Those functions are already defined in VPP in vnet/ip/ip_packet.h, and we
 * borrow this code here.
 */

static inline u16
ip_csum_fold (ip_csum_t c)
{
  /* Reduce to 16 bits. */
#if uword_bits == 64
  c = (c & (ip_csum_t) 0xffffffff) + (c >> (ip_csum_t) 32);
  c = (c & 0xffff) + (c >> 16);
#endif

  c = (c & 0xffff) + (c >> 16);
  c = (c & 0xffff) + (c >> 16);

  return (u16) c;
}

static inline ip_csum_t
ip_csum_with_carry (ip_csum_t sum, ip_csum_t x)
{
  ip_csum_t t = sum + x;
  return t + (t < x);
}

/* Update checksum changing field at even byte offset from x -> 0. */
static inline ip_csum_t
ip_csum_add_even (ip_csum_t c, ip_csum_t x)
{
  ip_csum_t d;

  d = c - x;

  /* Fold in carry from high bit. */
  d -= d > c;

  return d;
}

/* Update checksum changing field at even byte offset from 0 -> x. */
static inline ip_csum_t
ip_csum_sub_even (ip_csum_t c, ip_csum_t x)
{
  return ip_csum_with_carry (c, x);
}

#endif /* ! HICN_VPP_PLUGIN */

u32 cumulative_hash32 (const void *data, size_t len, u32 lastValue);
u32 hash32 (const void *data, size_t len);
u64 cumulative_hash64 (const void *data, size_t len, u64 lastValue);
u64 hash64 (const void *data, size_t len);
void hicn_packet_dump (const uint8_t *buffer, size_t len);

/**
 * @brief Computes buffer checksum
 * @param [in] addr - Pointer to buffer start
 * @param [in] size - Size of buffer
 * @param [in] init - Checksum initial value
 * @return Checksum of specified buffer
 */
static inline u16
csum (const void *addr, size_t size, u16 init)
{
  u32 sum = init;
  const u16 *bytes = (u16 *) addr;

  while (size > 1)
    {
      sum += *bytes++;
      size -= sizeof (u16);
    }
  if (size)
    {
      sum += *(const u8 *) bytes;
    }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  return (u16) ~sum;
}

/*
 * Useful aliases
 */

/* Symmetry with IPPROTO_ICMPV6 */
#define IPPROTO_ICMPV4 IPPROTO_ICMP

/*
 * Query IP version from packet (either 4 or 6)
 * (version is located as same offsets in both protocol headers)
 */
#define HICN_IP_VERSION(packet)                                               \
  ((hicn_header_t *) packet)->protocol.ipv4.version

/*
 * ntohll / htonll allows byte swapping for 64 bits integers
 */
#ifndef htonll
#define htonll(x)                                                             \
  ((1 == htonl (1)) ?                                                         \
	   (x) :                                                                    \
	   ((uint64_t) htonl ((x) &0xFFFFFFFF) << 32) | htonl ((x) >> 32))
#endif

#ifndef ntohll
#define ntohll(x)                                                             \
  ((1 == ntohl (1)) ?                                                         \
	   (x) :                                                                    \
	   ((uint64_t) ntohl ((x) &0xFFFFFFFF) << 32) | ntohl ((x) >> 32))
#endif

#endif /* HICN_COMMON_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
