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

#include <hicn/hicn.h>

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

#define HICN_BUFFER_FLAGS_DEFAULT 0x00
#define HICN_BUFFER_FLAGS_FACE_IS_APP 0x01
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

  dpo_id_t face_dpo_id;		/* ingress face ,sizeof(iface_dpo_id)
				 * <= sizeof(u64) */

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

#endif /* __HICN_H__ */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
