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

#include <vnet/ip/ip6_packet.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include "face_cons.h"
#include "address_mgr.h"
#include "../../infra.h"

int
hicn_face_cons_add (ip4_address_t * nh_addr4, ip6_address_t * nh_addr6,
		    u32 swif, hicn_face_id_t * faceid1,
		    hicn_face_id_t * faceid2)
{
  /* Create the corresponding appif if */
  /* Retrieve a valid local ip address to assign to the appif */
  /* Set the ip address and create the face in the face db */

  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();

  hicn_main_t *hm = &hicn_main;

  ip46_address_t if_ip;
  ip46_address_reset (&if_ip);
  nh_addr4->as_u32 = 0;
  nh_addr6->as_u64[0] = 0;
  nh_addr6->as_u64[1] = 0;
  u32 if_flags = 0;

  if (!hm->is_enabled)
    {
      return HICN_ERROR_FWD_NOT_ENABLED;
    }
  if_flags |= VNET_SW_INTERFACE_FLAG_ADMIN_UP;
  vnet_sw_interface_set_flags (vnm, swif, if_flags);

  get_two_ip4_addresses (&(if_ip.ip4), nh_addr4);
  ip4_add_del_interface_address (vm,
				 swif,
				 &(if_ip.ip4),
				 ADDR_MGR_IP4_CONS_LEN, 0 /* is_del */ );

  ip46_address_t nh_addr = to_ip46 (0, (u8 *) nh_addr4);

  hicn_iface_ip_add (&if_ip, &nh_addr, swif, faceid1);

  hicn_face_t *face = hicn_dpoi_get_from_idx (*faceid1);
  face->shared.flags |= HICN_FACE_FLAGS_APPFACE_CONS;

  get_two_ip6_addresses (&(if_ip.ip6), nh_addr6);
  ip6_add_del_interface_address (vm,
				 swif,
				 &(if_ip.ip6),
				 ADDR_MGR_IP6_CONS_LEN, 0 /* is_del */ );

  hicn_iface_ip_add (&if_ip, (ip46_address_t *) nh_addr6, swif, faceid2);

  face = hicn_dpoi_get_from_idx (*faceid2);
  face->shared.flags |= HICN_FACE_FLAGS_APPFACE_CONS;

  return HICN_ERROR_NONE;
}

int
hicn_face_cons_del (hicn_face_id_t face_id)
{
  if (!hicn_dpoi_idx_is_valid (face_id))
    return HICN_ERROR_APPFACE_NOT_FOUND;

  hicn_face_t *face = hicn_dpoi_get_from_idx (face_id);

  if (face->shared.flags & HICN_FACE_FLAGS_APPFACE_CONS)
    {
      return hicn_face_ip_del (face_id);
    }
  else
    {
      return HICN_ERROR_APPFACE_NOT_FOUND;
    }
}

u8 *
format_hicn_face_cons (u8 * s, va_list * args)
{
  CLIB_UNUSED (index_t index) = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  s = format (s, " (consumer face)");

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
