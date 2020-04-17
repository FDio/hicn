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

/*
 * Copyright (c) 2017-2019 by Cisco Systems Inc. All Rights Reserved.
 *
 */

#ifndef HICN_MAPME_CTRL_H
#define HICN_MAPME_CTRL_H

#include <vlib/vlib.h>
#include <vnet/vnet.h>

/* Node context data */
typedef struct hicn_mapme_ctrl_runtime_s
{
  int id;
} hicn_mapme_ctrl_runtime_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
} hicn_mapme_ctrl_trace_t;

typedef enum
{
  HICN_MAPME_CTRL_NEXT_IP4_OUTPUT,
  HICN_MAPME_CTRL_NEXT_IP6_OUTPUT,
  HICN_MAPME_CTRL_NEXT_ERROR_DROP,
  HICN_MAPME_CTRL_N_NEXT,
} hicn_mapme_ctrl_next_t;
/**
 * @brief Returns the next hop node on which we can send an ACK packet
 */
always_inline hicn_mapme_ctrl_next_t
hicn_mapme_ctrl_get_iface_node (hicn_face_id_t face_id)
{
  hicn_face_t * face  = hicn_dpoi_get_from_idx(face_id);

  switch (face->dpo.dpoi_proto)
    {
    case DPO_PROTO_IP4:
      return HICN_MAPME_CTRL_NEXT_IP4_OUTPUT;
    case DPO_PROTO_IP6:
      return HICN_MAPME_CTRL_NEXT_IP6_OUTPUT;
    default:
      return HICN_MAPME_CTRL_NEXT_ERROR_DROP;
    }
}

#endif /* HICN_MAPME_CTRL_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
