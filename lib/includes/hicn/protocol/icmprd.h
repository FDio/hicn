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
 * @file protocol/icmp-rd.c
 * @brief hICN operations for ICMP Redirect header
 */
#ifndef HICN_PROTOCOL_ICMPRD_H
#define HICN_PROTOCOL_ICMPRD_H

#include "../common.h"
#include "ipv4.h"

/*
 * The length of the ICMPRD4 header struct must be 92 bytes.
 */
#define EXPECTED_ICMPRD4_HDRLEN 92

typedef struct
{
  u8 type;
  u8 code;
  u16 csum;
  ip4_address_t ip;
  _ipv4_header_t iph;
  u8 data[64];
} _icmprd4_header_t;

#define ICMPRD4_HDRLEN sizeof(_icmprd4_header_t)
static_assert (EXPECTED_ICMPRD4_HDRLEN == ICMPRD4_HDRLEN,
	       "Size of ICMPWLDR struct does not match its expected size.");

/*
 * The length of the ICMPRD header struct must be 40 bytes.
 */
#define EXPECTED_ICMPRD_HDRLEN 40

typedef struct
{
  u8 type;
  u8 code;
  u16 csum;
  u32 res;
  ip6_address_t tgt;
  ip6_address_t dst;
} _icmprd_header_t;

#define ICMPRD_HDRLEN sizeof(_icmprd_header_t)
static_assert (EXPECTED_ICMPRD_HDRLEN == ICMPRD_HDRLEN,
	       "Size of ICMPWLDR struct does not match its expected size.");

#endif /* HICN_PROTOCOL_ICMPRD_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
