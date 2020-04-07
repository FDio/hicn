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

#ifndef __HICN_H__
#define __HICN_H__

#define ip_address_t hicn_ip_address_t
#define ip_address_cmp hicn_ip_address_cmp
#define ip_prefix_t hicn_ip_prefix_t
#define ip_prefix_cmp hicn_ip_prefix_cmp
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

/* Helper for avoiding warnings about type-punning */
#define UNION_CAST(x, destType) \
   (((union {__typeof__(x) a; destType b;})x).b)

/*
 * Update CMakeLists.txt as we have to manually replace the type for
 * vppapigen
 */
typedef u8 weight_t;

#define ISV6(isv6, dov6, dov4) isv6 ? dov6 : dov4
#define HICN_IS_NAMEHASH_CACHED(b) (((u64)(b->opaque2)[0] != 0) || ((u64)(b->opaque2)[1] != 0))

#ifndef VLIB_BUFFER_MIN_CHAIN_SEG_SIZE
#define VLIB_BUFFER_MIN_CHAIN_SEG_SIZE (128)
#endif

/* vlib_buffer cloning utilities impose that current_lentgh is more that 2*CLIB_CACHE_LINE_BYTES.  */
/* This flag is used to mark packets whose lenght is less that 2*CLIB_CACHE_LINE_BYTES. */
#define HICN_BUFFER_FLAGS_PKT_LESS_TWO_CL 0x02

/* The following is stored in the opaque2 field in the vlib_buffer_t */
typedef struct
{
  /* hash of the name */
  u64 name_hash;

  /* ids to prefetch a PIT/CS entry */
  u32 node_id;
  u32 bucket_id;
  u8 hash_entry_id;
  u8 hash_bucket_flags;

  u8 flags;
  u8 dpo_ctx_id;		/* used for data path */
  u8 vft_id;			/* " */

  hicn_face_id_t face_id;	/* ingress iface, sizeof(u32) */
  u32 in_faces_vec_id;          /* vector of possible input face for a data packet */

  hicn_type_t type;
} hicn_buffer_t;

STATIC_ASSERT (sizeof (hicn_buffer_t) <=
	       STRUCT_SIZE_OF (vlib_buffer_t, opaque2),
	       "hICN buffer opaque2 meta-data too large for vlib_buffer");


always_inline hicn_buffer_t *
hicn_get_buffer (vlib_buffer_t * b0)
{
  return (hicn_buffer_t *) & (b0->opaque2[0]);
}

always_inline u8
hicn_is_v6 (hicn_header_t * pkt_hdr)
{
  return ((pkt_hdr->v4.ip.version_ihl >> 4) != 4);
}

#endif /* __HICN_H__ */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
