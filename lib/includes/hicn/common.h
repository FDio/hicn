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

#include <hicn/util/types.h>

#define HICN_EXPECT_FALSE(x) __builtin_expect ((x), 1)
#define HICN_EXPECT_TRUE(x)  __builtin_expect ((x), 0)
#define HICN_UNUSED(x)	     x __attribute__ ((unused))

#ifndef NDEBUG
#define _ASSERT(x) assert (x)
#else
#define _ASSERT(x) ((void) (x))
#endif

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
ip_csum_fold (hicn_ip_csum_t c)
{
  /* Reduce to 16 bits. */
#if uword_bits == 64
  c = (c & (hicn_ip_csum_t) 0xffffffff) + (c >> (hicn_ip_csum_t) 32);
  c = (c & 0xffff) + (c >> 16);
#endif

  c = (c & 0xffff) + (c >> 16);
  c = (c & 0xffff) + (c >> 16);

  return (u16) c;
}

static inline hicn_ip_csum_t
ip_csum_with_carry (hicn_ip_csum_t sum, hicn_ip_csum_t x)
{
  hicn_ip_csum_t t = sum + x;
  return t + (t < x);
}

/* Update checksum changing field at even byte offset from x -> 0. */
static inline hicn_ip_csum_t
ip_csum_add_even (hicn_ip_csum_t c, hicn_ip_csum_t x)
{
  hicn_ip_csum_t d;

  d = c - x;

  /* Fold in carry from high bit. */
  d -= d > c;

  return d;
}

/* Update checksum changing field at even byte offset from 0 -> x. */
static inline hicn_ip_csum_t
ip_csum_sub_even (hicn_ip_csum_t c, hicn_ip_csum_t x)
{
  return ip_csum_with_carry (c, x);
}

#endif /* ! HICN_VPP_PLUGIN */

u32 cumulative_hash32 (const void *data, size_t len, u32 lastValue);
u32 hash32 (const void *data, size_t len);
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
typedef struct
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  u8 dummy : 4;
  u8 version : 4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  u8 version : 4;
  u8 dummy : 4;
#else
#error "Unsupported endianness"
#endif
} ip_version_t;
#define HICN_IP_VERSION(packet) ((ip_version_t *) packet)->version

/*
 * Endianess utils
 */

#if (__BYTE_ORDER__) == (__ORDER_LITTLE_ENDIAN__)
#define HICN_LITTLE_ENDIAN_ARCH
#else
#define HICN_BIG_ENDIAN_ARCH
#endif

static inline u16
hicn_conditional_swap_u16 (u16 value)
{
#ifdef HICN_LITTLE_ENDIAN_ARCH
  value = __builtin_bswap16 (value);
#endif

  return value;
}

static inline u32
hicn_conditional_swap_u32 (u32 value)
{
#ifdef HICN_LITTLE_ENDIAN_ARCH
  value = __builtin_bswap32 (value);
#endif

  return value;
}

static inline u64
hicn_conditional_swap_u64 (u64 value)
{
#ifdef HICN_LITTLE_ENDIAN_ARCH
  value = __builtin_bswap64 (value);
#endif

  return value;
}

#define hicn_net_to_host_16(x) hicn_conditional_swap_u16 ((u16) (x))
#define hicn_net_to_host_32(x) hicn_conditional_swap_u32 ((u32) (x))
#define hicn_net_to_host_64(x) hicn_conditional_swap_u64 ((u64) (x))

#define hicn_host_to_net_16(x) hicn_conditional_swap_u16 ((u16) (x))
#define hicn_host_to_net_32(x) hicn_conditional_swap_u32 ((u32) (x))
#define hicn_host_to_net_64(x) hicn_conditional_swap_u64 ((u64) (x))

#define hicn_round_pow2(x, pow2) (((x) + (pow2) -1) & ~((pow2) -1))

#define _SIZEOF_ALIGNED(x, size) hicn_round_pow2 (sizeof (x), size)
#define SIZEOF_ALIGNED(x)	 _SIZEOF_ALIGNED (x, sizeof (void *))

/* Definitions for builtins unavailable on MSVC */
#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>

uint32_t __inline __builtin_ctz (uint32_t value)
{
  uint32_t trailing_zero = 0;
  if (_BitScanForward (&trailing_zero, value))
    return trailing_zero;
  else
    return 32;
}

uint32_t __inline __builtin_clz (uint32_t value)
{
  uint32_t leading_zero = 0;
  if (_BitScanReverse (&leading_zero, value))
    return 31 - leading_zero;
  else
    return 32;
}

uint32_t __inline __builtin_clzl2 (uint64_t value)
{
  uint32_t leading_zero = 0;
  if (_BitScanReverse64 (&leading_zero, value))
    return 63 - leading_zero;
  else
    return 64;
}

#define __builtin_clzl __builtin_clzll
#endif

#define next_pow2(x) (x <= 1 ? 1 : 1ul << (64 - __builtin_clzl (x - 1)))
#define _unused(x)   ((void) (x))

#endif /* HICN_COMMON_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
