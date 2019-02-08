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
 * @file protocol/icmp.h
 * @brief ICMP packet header
 */
#ifndef HICN_PROTOCOL_ICMP_H
#define HICN_PROTOCOL_ICMP_H

#include "../common.h"

typedef struct
{
  u8 type;
  u8 code;
  u16 csum;
} _icmp_header_t;

typedef struct
{
  u8 type;
  u8 code;
  u16 csum;
  union
  {
    struct
    {
      u16 id;
      u16 sequence;
    } echo;			/* echo datagram */
    u32 gateway;		/* gateway address */
    struct
    {
      u16 _unused;
      u16 mtu;
    } frag;			/* path mtu discovery */
    struct
    {
      u16 expected_lbl;
      u16 received_lbl;
    } wldr_notification_lbl;
  };
} _icmp_wldr_header_t;

#define ICMP_HDRLEN sizeof(_icmp_header_t)

#endif /* HICN_PROTOCOL_ICMP_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
