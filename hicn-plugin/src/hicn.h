/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#define ip_address_t   hicn_ip_address_t
#define ip_address_cmp hicn_ip_address_cmp
#define ip_prefix_t    hicn_ip_prefix_t
#define ip_prefix_cmp  hicn_ip_prefix_cmp
#undef ip_prefix_len
#define ip_prefix_len hicn_ip_prefix_len
#include <hicn/hicn.h>
#undef ip_address_t
#undef ip_address_cmp
#undef ip_prefix_t
#undef ip_prefix_cmp
#undef ip_prefix_len
#define ip_prefix_len(_a) (_a)->len

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
   * Hash of the name (8)
   */
  u64 name_hash;

  /**
   * IDs to prefetch a PIT/CS entry (4+4+1+1)
   */
  u32 node_id;
  u32 bucket_id;
  u8 hash_entry_id;
  u8 hash_bucket_flags;

  /**
   * hICN buffer flags (1)
   */
  u8 flags;

  /**
   * used for data path (1+1)
   */
  u8 dpo_ctx_id;
  u8 vft_id;

  /**
   * Ingress face (4)
   */
  hicn_face_id_t face_id;

  /**
   * Cached packet info
   */
  hicn_type_t type;
  hicn_name_t name;
  u16 port;
} hicn_buffer_t;

STATIC_ASSERT (sizeof (hicn_buffer_t) <=
		 STRUCT_SIZE_OF (vlib_buffer_t, opaque2),
	       "hICN buffer opaque2 meta-data too large for vlib_buffer");

always_inline hicn_buffer_t *
hicn_get_buffer (vlib_buffer_t *b0)
{
  return (hicn_buffer_t *) &(b0->opaque2[0]);
}

always_inline u8
hicn_is_v6 (hicn_header_t *pkt_hdr)
{
  return ((pkt_hdr->v4.ip.version_ihl >> 4) != 4);
}

always_inline void
hicn_buffer_get_name_and_namelen (vlib_buffer_t *b0, u8 **nameptr,
				  u16 *namelen)
{
  *nameptr = (u8 *) (&hicn_get_buffer (b0)->name);
  *namelen = ip_address_is_v4 (&hicn_get_buffer (b0)->name.prefix) ?
		     HICN_V4_NAME_LEN :
		     HICN_V6_NAME_LEN;
}

always_inline u8
hicn_buffer_is_v6 (vlib_buffer_t *b0)
{
  return hicn_get_buffer (b0)->type.l1 == IPPROTO_IPV6;
}

always_inline void
hicn_buffer_set_flags (vlib_buffer_t *b, u8 flags)
{
  hicn_buffer_t *hb = hicn_get_buffer (b);
  hb->flags |= flags;
}
#endif /* __HICN_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
