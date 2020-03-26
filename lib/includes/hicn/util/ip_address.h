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
 * \brief IP address type
 */
#ifndef UTIL_IP_ADDRESS_H
#define UTIL_IP_ADDRESS_H


#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define __bswap_constant_32(x) OSSwapInt32(x)
#include <machine/endian.h>
#else
#ifdef __ANDROID__
#include <byteswap.h>
#endif

#endif
#include <errno.h>

#ifndef _WIN32
#include <netinet/in.h>        // struct sockadd
#include <arpa/inet.h>  // inet_ntop
#include <netdb.h> // struct addrinfo
#endif
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h> // snprintf
#include <string.h> // memset

#include "types.h"

#define bytes_to_bits(x) (x * 8)
#define IPV6_ADDR_LEN 16    /* bytes */
#define IPV4_ADDR_LEN 4        /* bytes */
#define IPV6_ADDR_LEN_BITS bytes_to_bits(IPV6_ADDR_LEN)
#define IPV4_ADDR_LEN_BITS bytes_to_bits(IPV4_ADDR_LEN)

/* Presentation format */
#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif
//#define INET_MAX_ADDRSTRLEN INET6_ADDRSTRLEN

#define IP_MAX_ADDR_LEN IPV6_ADDR_LEN

#define DUMMY_PORT 1234

typedef union {
    struct {
        u32 pad[3];
        union {
                struct in_addr as_inaddr;
                u8 buffer[4];
                u8 as_u8[4];
                u16 as_u16[2];
                u32 as_u32;
        } v4;
    };
    union {
        struct in6_addr as_in6addr;
        u8 buffer[16];
        u8 as_u8[16];
        u16 as_u16[8];
        u32 as_u32[4];
        u64 as_u64[2];
    } v6;
#if 0 /* removed as prone to error due to IPv4 padding */
    u8 buffer[IP_MAX_ADDR_LEN];
    u8 as_u8[IP_MAX_ADDR_LEN];
    u16 as_u16[IP_MAX_ADDR_LEN >> 1];
    u32 as_u32[IP_MAX_ADDR_LEN >> 2];
    u64 as_u64[IP_MAX_ADDR_LEN >> 3];
#endif
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

extern const ip_address_t IPV4_LOOPBACK;
extern const ip_address_t IPV6_LOOPBACK;
extern const ip_address_t IPV4_ANY;
extern const ip_address_t IPV6_ANY;
extern const ip_address_t IP_ADDRESS_EMPTY;

#define IP_ANY(family) (family == AF_INET) ? IPV4_ANY : IPV6_ANY


#define MAX_PORT 1 << (8 * sizeof(u16))
#define IS_VALID_PORT(x) ((x > 0) && ((int)x < MAX_PORT))

#define MAXSZ_PORT_ 5
#define MAXSZ_PORT MAXSZ_PORT_ + 1

#define IS_VALID_FAMILY(x) ((x == AF_INET) || (x == AF_INET6))

/* IP address */

int ip_address_get_family (const char * ip_address);
int ip_address_len (int family);
const u8 * ip_address_get_buffer(const ip_address_t * ip_address, int family);
int ip_address_ntop (const ip_address_t * ip_address, char *dst,
        const size_t len, int family);
int ip_address_pton (const char *ip_address_str, ip_address_t * ip_address);
int ip_address_snprintf(char * s, size_t size, const ip_address_t * ip_address,
        int family);
int ip_address_to_sockaddr(const ip_address_t * ip_address, struct sockaddr *sa,
        int family);
int ip_address_cmp(const ip_address_t * ip1, const ip_address_t * ip2, int family);
int ip_address_empty(const ip_address_t * ip);

/* Prefix */

int ip_prefix_pton (const char *ip_address_str, ip_prefix_t * ip_prefix);
int ip_prefix_ntop_short (const ip_prefix_t * ip_prefix, char *dst, size_t size);
int ip_prefix_ntop (const ip_prefix_t * ip_prefix, char *dst, size_t size);
int ip_prefix_len (const ip_prefix_t * prefix);
bool ip_prefix_empty (const ip_prefix_t * prefix);
int ip_prefix_to_sockaddr(const ip_prefix_t * prefix, struct sockaddr *sa);
int ip_prefix_cmp(const ip_prefix_t * prefix1, const ip_prefix_t * prefix2);

/* URL */

#define MAXSZ_PROTO_ 8 /* inetX:// */
#define MAXSZ_PROTO MAXSZ_PROTO_ + NULLTERM

#define MAXSZ_URL4_ MAXSZ_PROTO_ + MAXSZ_IP4_ADDRESS_ + MAXSZ_PORT_
#define MAXSZ_URL6_ MAXSZ_PROTO_ + MAXSZ_IP6_ADDRESS_ + MAXSZ_PORT_
#define MAXSZ_URL_ MAXSZ_URL6_
#define MAXSZ_URL4 MAXSZ_URL4_ + NULLTERM
#define MAXSZ_URL6 MAXSZ_URL6_ + NULLTERM
#define MAXSZ_URL MAXSZ_URL_ + NULLTERM

int url_snprintf(char * s, size_t size, int family,
        const ip_address_t * ip_address, u16 port);

#endif /* UTIL_IP_ADDRESS_H */
