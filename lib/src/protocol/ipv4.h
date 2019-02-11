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

#ifndef HICN_PROTOCOL_IPV4
#define HICN_PROTOCOL_IPV4

#include "../base.h"
#include "../common.h"
#include "../protocol.h"

/* Headers were adapted from linux' definitions in netinet/ip.h */

PACKED(
struct _ipv4_header_s
{
  union
  {
    struct
    {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
      u8 ihl:4;
      u8 version:4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
      u8 version:4;
      u8 ihl:4;
#else
#error "Unsupported endianness"
#endif
    };

    u8 version_ihl;
  };
  u8 tos;
  u16 len;
  u16 id;
  u16 frag_off;
  u8 ttl;
  u8 protocol;
  u16 csum;
  ip4_address_t saddr;
  ip4_address_t daddr;
});
typedef struct _ipv4_header_s _ipv4_header_t;

#define ipv4_header_bytes(ipv4_header) (sizeof(u32) * (ipv4_header->version_ihl & 0xf))

#define IPV4_HDRLEN sizeof(_ipv4_header_t)

typedef struct
{
  ip4_address_t ip_src;
  ip4_address_t ip_dst;
  u8 zero;
  u8 protocol;
  u16 size;
} ipv4_pseudo_header_t;

#define IPV4_PSHDRLEN sizeof(ipv4_pseudo_header_t)

/* Default field values */
#define IPV4_DEFAULT_VERSION         4
#define IPV4_DEFAULT_IHL             5
#define IPV4_DEFAULT_TOS             0
#define IPV4_DEFAULT_PAYLOAD_LENGTH  0
#define IPV4_DEFAULT_ID              300
#define IPV4_DEFAULT_FRAG_OFF        0x000
#define IPV4_DEFAULT_TTL             64
#define IPV4_DEFAULT_PROTOCOL        IPPROTO_TCP
#define IPV4_DEFAULT_SRC_IP          0, 0, 0, 0
#define IPV4_DEFAULT_DST_IP          0, 0, 0, 0


#endif /* HICN_PROTOCOL_IPV4 */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
