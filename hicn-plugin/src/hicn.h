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

#ifndef __HICN_H__
#define __HICN_H__

#include <hicn/hicn.h>
#include "faces/face.h"

#include <netinet/in.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/buffer.h>

/**
 * @file
 */

/*
 * Update CMakeLists.txt as we have to manually replace the type for
 * vppapigen
 */
typedef u8 weight_t;

#define ISV6(isv6, dov6, dov4) isv6 ? dov6 : dov4
#define HICN_IS_NAMEHASH_CACHED(b)                                            \
  (((u64) (b->opaque2)[0] != 0) || ((u64) (b->opaque2)[1] != 0))

#ifndef VLIB_BUFFER_MIN_CHAIN_SEG_SIZE
#define VLIB_BUFFER_MIN_CHAIN_SEG_SIZE (128)
#endif

/* The following is stored in the opaque2 field in the vlib_buffer_t */
typedef struct
{
  /**
   * Cached packet info
   */
  hicn_packet_buffer_t pkbuf;

  /**
   * IDs to prefetch a PIT/CS entry (4)
   */
  u32 pcs_entry_id;

  /**
   * DPO/Stategy VFT ID. This is also the DPO type (4)
   */
  dpo_type_t vft_id;

  /**
   * DPO context ID (4)
   */
  u32 dpo_ctx_id;

  /**
   * hICN buffer flags (1)
   */
  u8 flags;

  /**
   * Ingress face (4)
   */
  hicn_face_id_t face_id;

  /*
  hicn_packet_type_t type;
  hicn_packet_format_t format;
  hicn_name_t name;
  */
  u16 port;
  hicn_lifetime_t lifetime;
} hicn_buffer_t;

STATIC_ASSERT (offsetof (hicn_buffer_t, pcs_entry_id) == 28, "");
STATIC_ASSERT (offsetof (hicn_buffer_t, vft_id) == 32, "");
STATIC_ASSERT (offsetof (hicn_buffer_t, dpo_ctx_id) == 36, "");
STATIC_ASSERT (offsetof (hicn_buffer_t, flags) == 40, "");
STATIC_ASSERT (offsetof (hicn_buffer_t, face_id) == 44, "");
// STATIC_ASSERT (offsetof (hicn_buffer_t, name) == 48, "");
// + name = 16+4 = 20
// opaque : u32[14] = 56
STATIC_ASSERT (sizeof (hicn_buffer_t) <=
		 STRUCT_SIZE_OF (vlib_buffer_t, opaque2),
	       "hICN buffer opaque2 meta-data too large for vlib_buffer");

always_inline hicn_buffer_t *
hicn_get_buffer (vlib_buffer_t *b0)
{
  return (hicn_buffer_t *) &(b0->opaque2[0]);
}

#if 0
always_inline u8
hicn_is_v6 (hicn_header_t *pkt_hdr)
{
  return ((pkt_hdr->v4.ip.version_ihl >> 4) != 4);
}

always_inline hicn_name_t *
hicn_buffer_get_name (vlib_buffer_t *b)
{
  return hicn_packet_get_name(&hicn_get_buffer (b)->pkbuf);
}
#endif

always_inline u8
hicn_buffer_is_v6 (vlib_buffer_t *b0)
{
  hicn_packet_format_t format =
    hicn_packet_get_format (&hicn_get_buffer (b0)->pkbuf);
  return format.l1 == IPPROTO_IPV6;
}

always_inline void
hicn_buffer_set_flags (vlib_buffer_t *b, u8 flags)
{
  hicn_buffer_t *hb = hicn_get_buffer (b);
  hb->flags |= flags;
}

always_inline hicn_lifetime_t
hicn_buffer_get_lifetime (vlib_buffer_t *b)
{
  return hicn_get_buffer (b)->lifetime;
}

#endif /* __HICN_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
