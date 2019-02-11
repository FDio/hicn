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

PACKED(
struct _icmprd4_header_s
{
  ip4_address_t ip;
  _ipv4_header_t iph;
  u8 data[64];
});
typedef struct _icmprd4_header_s _icmprd4_header_t;

PACKED(
struct _icmprd_header_s
{
  u32 res;
  ip6_address_t tgt;
  ip6_address_t dst;
});
typedef struct _icmprd_header_s _icmprd_header_t;

#endif /* HICN_PROTOCOL_ICMPRD_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
