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

#ifndef HICN_PROTOCOL_TCP_H
#define HICN_PROTOCOL_TCP_H

#include "../base.h"
#include "../common.h"
#include "../name.h"

/*
 * The length of the TCP header struct must be 20 bytes.
 */
#define EXPECTED_TCP_HDRLEN 20

/*
 * NOTE: bitfields are problematic for portability reasons. There are provided
 * here for reference and documentation purposes, we might just provide a macro
 * to disable and use it instead of __BYTE_ORDER__.
 */
typedef struct
{
  u16 sport;
  u16 dport;
  union
  {
    u32 seq;
    hicn_name_suffix_t name_suffix;
  };
  union
  {
    u32 seq_ack;
    hicn_pathlabel_t pathlabel;
  };

  union
  {
    struct
    {
      u8 data_offset_and_reserved;
      u8 flags;
    };
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    struct
    {
      u16 reserved:4;
      u16 doff:4;
      u16 fin:1;
      u16 syn:1;
      u16 rst:1;
      u16 psh:1;
      u16 ack:1;
      u16 urg:1;
      u16 ece:1;
      u16 cwr:1;
    };
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
      u16 doff:4;
      u16 reserved:4;
      u16 cwr:1;
      u16 ece:1;
      u16 urg:1;
      u16 ack:1;
      u16 psh:1;
      u16 rst:1;
      u16 syn:1;
      u16 fin:1;
    };
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
  union
  {
    u16 window;
    u16 ldr;
  };
  u16 csum;
  union
  {
    u16 urg_ptr;
    u16 lifetime;
  };
} _tcp_header_t;

#define TCP_HDRLEN sizeof(_tcp_header_t)
static_assert (EXPECTED_TCP_HDRLEN == TCP_HDRLEN,
	       "Size of TCP struct does not match its expected size.");

#ifndef HICN_VPP_PLUGIN

/* TCP flags bit 0 first. */
#define foreach_tcp_flag                                \
          _ (FIN) /**< No more data from sender. */             \
      _ (SYN) /**< Synchronize sequence numbers. */         \
      _ (RST) /**< Reset the connection. */                 \
      _ (PSH) /**< Push function. */                        \
      _ (ACK) /**< Ack field significant. */                \
      _ (URG) /**< Urgent pointer field significant. */     \
      _ (ECE) /**< ECN-echo. Receiver got CE packet */      \
      _ (CWR) /**< Sender reduced congestion window */

enum
{
#define _(f) HICN_TCP_FLAG_BIT_##f,
  foreach_tcp_flag
#undef _
    HICN_TCP_N_FLAG_BITS,
};

enum
{
#define _(f) HICN_TCP_FLAG_##f = 1 << HICN_TCP_FLAG_BIT_##f,
  foreach_tcp_flag
#undef _
};

#endif /* HICN_VPP_PLUGIN */

// get_data_name_suffix
// name->ip4.suffix = h->v4.tcp.seq;


#endif /* HICN_PROTOCOL_TCP_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
