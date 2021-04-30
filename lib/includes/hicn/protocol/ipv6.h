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

#ifndef HICN_PROTOCOL_IPV6_H
#define HICN_PROTOCOL_IPV6_H

#include "../common.h"

/*
 * The length of the IPV6 header struct must be 40 bytes.
 */
#define EXPECTED_IPV6_HDRLEN 40

typedef struct
{
  union
  {
    struct
    {
      u32 version_class_flow;	/* version, traffic class and 20 bits of flow-ID */
      u16 len;			/* payload length */
      u8 nxt;			/* next header */
      u8 hlim;			/* hop limit */
    };
    u8 vfc;			/* 4 bits version, top 4 bits class */
  };
  ip6_address_t saddr;		/* source address */
  ip6_address_t daddr;		/* destination address */
} _ipv6_header_t;

#define IPV6_HDRLEN sizeof(_ipv6_header_t)
static_assert (EXPECTED_IPV6_HDRLEN == IPV6_HDRLEN,
	       "Size of IPV6 struct does not match its expected size.");

/*
 * The length of the IPV6 pseudo header struct must be 40 bytes.
 */
#define EXPECTED_IPV6_PSHDRLEN 40

typedef struct
{
  ip6_address_t ip_src;
  ip6_address_t ip_dst;
  u32 size;
  u16 zeros;
  u8 zero;
  u8 protocol;
} ipv6_pseudo_header_t;

#define IPV6_PSHDRLEN sizeof(ipv6_pseudo_header_t)
static_assert (EXPECTED_IPV6_PSHDRLEN == IPV6_PSHDRLEN,
	       "Size of IPV6_PSHDR struct does not match its expected size.");

/* Default field values */
#define IPV6_DEFAULT_VERSION         6
#define IPV6_DEFAULT_TRAFFIC_CLASS   0
#define IPV6_DEFAULT_FLOW_LABEL      0
#define IPV6_DEFAULT_PAYLOAD_LENGTH  0

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
