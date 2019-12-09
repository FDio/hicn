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

#ifndef HICN_PROTOCOL_UDP_H
#define HICN_PROTOCOL_UDP_H

#include <stddef.h>

#include "../base.h"
#include "../name.h"

/*
 * The length of the UDP header struct must be 8 bytes.
 */
#define EXPECTED_UDP_HDRLEN 8

typedef struct
{
  u16 sport;
  u16 dport;
  u16 length;
  u16 csum;
} _udp_header_t;

#define UDP_HDRLEN sizeof(_udp_header_t)
static_assert (EXPECTED_UDP_HDRLEN == UDP_HDRLEN,
	       "Size of UDP struct does not match its expected size.");

/* Reference: https://tools.ietf.org/html/draft-muscariello-intarea-hicn#section-2.3 */
typedef struct
{
  u16 sport;
  u16 dport;
  u16 length;
  u16 csum;
  hicn_name_suffix_t name_suffix;
  hicn_pathlabel_t pathlabel;
  union
  {
    struct
    {
      u8 data_offset_and_reserved;
      u8 flags;
    };
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    struct
    {				/* __ denotes unchanged bitfields */
      u16 timescale:4;
      u16 __doff:4;
      u16 __fin:1;
      u16 __syn:1;
      u16 __rst:1;
      u16 sig:1;
      u16 __ack:1;
      u16 man:1;
      u16 id:1;
      u16 __cwr:1;
    };
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    struct
    {
      u16 __doff:4;
      u16 timescale:4;
      u16 __cwr:1;
      u16 id:1 u16 man:1;
      u16 __ack:1;
      u16 sig:1;
      u16 __rst:1;
      u16 __syn:1;
      u16 __fin:1;
    };
#endif
  };
  u16 ldr;
  u16 csum_unused;
  u16 lifetime;
} _udp_hicn_header_t;

#endif /* HICN_PROTOCOL_UDP_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
