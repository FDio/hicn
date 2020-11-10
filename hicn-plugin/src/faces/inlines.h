/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __HICN_FACE_INLINES_H__
#define __HICN_FACE_INLINES_H__

#include <vlib/buffer.h>

always_inline void
ensure_offload_flags (vlib_buffer_t * b, int is_v4)
{
  b->flags |= VNET_BUFFER_F_OFFLOAD_TCP_CKSUM;
  b->flags |= is_v4 * VNET_BUFFER_F_OFFLOAD_IP_CKSUM;
  size_t l3_header_size = is_v4 * sizeof(ip4_header_t) + (!is_v4) * sizeof(ip6_header_t);

  /* Make sure l3_hdr_offset and l4_hdr_offset are set */
  if (!(b->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID))
    {
      b->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID;
      vnet_buffer(b)->l3_hdr_offset = b->current_data;
    }
  if (!(b->flags & VNET_BUFFER_F_L4_HDR_OFFSET_VALID))
    {
      b->flags |= VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      vnet_buffer(b)->l4_hdr_offset =
          vnet_buffer(b)->l3_hdr_offset + l3_header_size;
    }
}

#endif /* __HICN_FACE_INLINES_H__ */