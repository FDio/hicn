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

#include <vnet/ip/ip6_packet.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/interface_funcs.h>

#include "face_prod.h"
#include "address_mgr.h"
#include "../../infra.h"
#include "../../route.h"
#include "../../cache_policies/cs_lru.h"

mhash_t face_state_table;

/* used to check if an interface is already in the vector */
u32 *swif_state_vec;

static int
hicn_app_state_enable_data_receive (u32 swif, u8 is_ip4)
{
  int ret = HICN_ERROR_NONE;
  if (is_ip4)
    {
      ret = vnet_feature_enable_disable ("ip4-local", "hicn-face-prod-input",
					 swif, 1, 0, 0);
    }
  else
    {
      ret = vnet_feature_enable_disable ("ip6-local", "hicn-face-prod-input",
					 swif, 1, 0, 0);
    }

  return ret;
}

static int
hicn_app_state_disable_data_receive (u32 swif, u8 is_ip4)
{
  int ret = HICN_ERROR_NONE;
  if (is_ip4)
    {
      ret = vnet_feature_enable_disable ("ip4-local", "hicn-face-prod-input",
					 swif, 0, 0, 0);
    }
  else
    {
      ret = vnet_feature_enable_disable ("ip6-local", "hicn-face-prod-input",
					 swif, 0, 0, 0);
    }

  return ret;
}

static int
hicn_app_state_create (hicn_face_t *face, fib_prefix_t *prefix, u16 port)
{
  int ret = HICN_ERROR_NONE;
  hicn_face_id_t face_id = ~0;

  // Check the ref count of producer faces currently using the provided swif
  if (swif_state_vec[face->sw_if] == 0)
    {
      ret = hicn_app_state_enable_data_receive (
	face->sw_if, ip46_address_is_ip4 (&(prefix->fp_addr)));
      if (ret)
	{
	  goto end;
	}
    }
  swif_state_vec[face->sw_if]++;

  // Create the app state and store in the table
  face_id = hicn_dpoi_get_index (face);
  face_state_table_add (face->randomized_port, face->sw_if, face_id, prefix,
			face->dpo.dpoi_index);

end:
  return ret;
}

static int
hicn_app_state_del (const ip46_address_t *nat_addr, u16 port, u32 swif,
		    hicn_face_prod_state_t *deleted_state)
{
  // Decrement ref count of local app faces currently using swif
  if (swif_state_vec[swif] == 0)
    {
      return HICN_ERROR_APPFACE_NOT_FOUND;
    }

  swif_state_vec[swif]--;
  ASSERT (swif_state_vec[swif] != ~0);

  // Delete the hash table entry
  int ret = face_state_table_del (port, swif, deleted_state);
  if (ret != HICN_ERROR_NONE)
    {
      return ret;
    }

  // If ref counter reaches 0, disable the feature to receive data on this
  // interface
  ret =
    hicn_app_state_disable_data_receive (swif, ip46_address_is_ip4 (nat_addr));

  return ret;
}

int
hicn_face_prod_add (fib_prefix_t *prefix, u32 sw_if, u32 *cs_reserved,
		    ip46_address_t *prod_addr, hicn_face_id_t *face_id,
		    u16 port)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();

  hicn_main_t *hm = &hicn_main;

  // validate port
  assert (port >= 1024 && port < 65535);

  ip46_address_t local_app_ip = { .as_u64 = { 0, 0 } };
  CLIB_UNUSED (ip46_address_t remote_app_ip);
  u32 if_flags = 0;
  u8 face_exists = 0;
  hicn_face_id_t *vec_faces = NULL;

  if (!hm->is_enabled)
    {
      return HICN_ERROR_FWD_NOT_ENABLED;
    }

  if (vnet_get_sw_interface_or_null (vnm, sw_if) == NULL)
    {
      return HICN_ERROR_FACE_HW_INT_NOT_FOUND;
    }

  int ret = HICN_ERROR_NONE;
  hicn_face_t *face = NULL;

  if_flags |= VNET_SW_INTERFACE_FLAG_ADMIN_UP;
  vnet_sw_interface_set_flags (vnm, sw_if, if_flags);

#ifdef HICN_DDEBUG
  u8 *s0;
  s0 = format (0, "Prefix %U", format_fib_prefix, prefix);
  HICN_DEBUG ("Received request for %s, swif %d, port: %d\n", s0, sw_if, port);
#endif

  if (ip46_address_is_zero (&prefix->fp_addr))
    {
      return HICN_ERROR_APPFACE_PROD_PREFIX_NULL;
    }

  u8 isv6 = !ip46_address_is_ip4 (&prefix->fp_addr);
  index_t adj_index =
    adj_nbr_find (isv6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4,
		  isv6 ? VNET_LINK_IP6 : VNET_LINK_IP4, prod_addr, sw_if);

  // Check if a producer face is already existing for the same prefix
  // and sw_if
  face = hicn_face_get (&(prefix->fp_addr), port, sw_if, &hicn_face_hashtb,
			adj_index);

  if (face != NULL)
    {
      // Face exists already

      if (!(face->flags & HICN_FACE_FLAGS_DELETED))
	return HICN_ERROR_FACE_ALREADY_CREATED;

      // Something went wrong, a consumer face exists for the
      // producer's prefix. This should never happens, this is a safety check.
      if (face->flags & HICN_FACE_FLAGS_APPFACE_CONS)
	return HICN_ERROR_FACE_ALREADY_CREATED;

      // If the face exists but is marked as deleted, undelete it
      if (face->flags & HICN_FACE_FLAGS_DELETED)
	{
	  // remove the deleted flag and retrieve the face
	  // local addr
	  face->flags &= HICN_FACE_FLAGS_DELETED;
	}

      face_exists = 1;
      *face_id = hicn_dpoi_get_index (face);
    }
  else
    {
      // Create the face. Get 2 IP addresses, one for the local size and one
      // for the remote side. We choose v4 or v6 depending on the address
      // family of the producer route.
      if (ip46_address_is_ip4 (&prefix->fp_addr))
	{
	  ip4_address_t local_app_ip4;
	  ip4_address_t remote_app_ip4;
	  get_two_ip4_addresses (&local_app_ip4, &remote_app_ip4);
	  ip4_add_del_interface_address (vm, sw_if, &local_app_ip4, 31,
					 0 /* is_del */);
	  local_app_ip = to_ip46 (/* isv6 */ 0, local_app_ip4.as_u8);
	  remote_app_ip = to_ip46 (/* isv6 */ 0, remote_app_ip4.as_u8);

	  vnet_build_rewrite_for_sw_interface (vnm, sw_if, VNET_LINK_IP4,
					       &remote_app_ip4);
	}
      else
	{
	  ip6_address_t local_app_ip6;
	  ip6_address_t remote_app_ip6;
	  get_two_ip6_addresses (&local_app_ip6, &remote_app_ip6);
	  u8 *s0;
	  s0 = format (0, "%U", format_ip6_address, &local_app_ip6);

	  vlib_cli_output (vm, "Setting ip address %s\n", s0);

	  ip6_add_del_interface_address (vm, sw_if, &local_app_ip6, 127,
					 0 /* is_del */);
	  local_app_ip = to_ip46 (/* isv6 */ 1, local_app_ip6.as_u8);
	  remote_app_ip = to_ip46 (/* isv6 */ 1, remote_app_ip6.as_u8);
	}

      // Construct the rpath vector with the remote address as next hop
      fib_route_path_t rpath = { 0 };
      fib_route_path_t *rpaths = NULL;

      rpath.frp_weight = 1;
      rpath.frp_sw_if_index = sw_if;

      if (ip46_address_is_ip4 (&(prefix->fp_addr)))
	{
	  ip4_address_t mask;
	  ip4_preflen_to_mask (prefix->fp_len, &mask);
	  prefix->fp_addr.ip4.as_u32 =
	    prefix->fp_addr.ip4.as_u32 & mask.as_u32;
	  prefix->fp_proto = FIB_PROTOCOL_IP4;

	  rpath.frp_addr.ip4.as_u32 = remote_app_ip.ip4.as_u32;
	  rpath.frp_proto = DPO_PROTO_IP4;
	}
      else
	{
	  ip6_address_t mask;
	  ip6_preflen_to_mask (prefix->fp_len, &mask);
	  prefix->fp_addr.ip6.as_u64[0] =
	    prefix->fp_addr.ip6.as_u64[0] & mask.as_u64[0];
	  prefix->fp_addr.ip6.as_u64[1] =
	    prefix->fp_addr.ip6.as_u64[1] & mask.as_u64[1];
	  prefix->fp_proto = FIB_PROTOCOL_IP6;

	  rpath.frp_addr.ip6.as_u64[0] = remote_app_ip.ip6.as_u64[0];
	  rpath.frp_addr.ip6.as_u64[1] = remote_app_ip.ip6.as_u64[1];
	  rpath.frp_proto = DPO_PROTO_IP6;
	}

      vec_add1 (rpaths, rpath);

      // Add route to main FIB
      u32 fib_index = fib_table_find (prefix->fp_proto, 0);
      fib_table_entry_path_add2 (fib_index, prefix, FIB_SOURCE_CLI,
				 FIB_ENTRY_FLAG_NONE, rpaths);

      // Enable the prefix to trigger the copy of the router to the hICN VRF
      // and creste the corresponding face
      HICN_DEBUG ("Calling hicn enable for producer face");
      ret = hicn_route_enable_with_port (prefix, port, &vec_faces);
      if (ret)
	{
	  if (vec_faces != NULL)
	    vec_free (vec_faces);
	  return ret;
	}

      // We added 1 single path for this route, so we expect 1 face created
      ASSERT (vec_len (vec_faces) == 1);
      *face_id = vec_faces[0];

      // The producer address is the local app ip
      *prod_addr = local_app_ip;

      face_exists = 0;
    }

  face =
    hicn_face_get (&local_app_ip, port, sw_if, &hicn_face_hashtb, adj_index);
  assert (face);

  *face_id = hicn_dpoi_get_index (face);

  // Set the face flags
  face->flags |= HICN_FACE_FLAGS_APPFACE_PROD;
  face->saved_port = 0;
  face->randomized_port = port;

  // If the face is not new, create the app state for this producer face
  if (!face_exists)
    {
      hicn_app_state_create (face, prefix, port);
    }

  if (vec_faces != NULL)
    vec_free (vec_faces);

  return ret;
}

int
hicn_face_prod_del (hicn_face_id_t face_id)
{
  if (!hicn_dpoi_idx_is_valid (face_id))
    return HICN_ERROR_APPFACE_NOT_FOUND;

  int ret = HICN_ERROR_NONE;
  uword _deleted_state[CLIB_CACHE_LINE_BYTES];
  hicn_face_prod_state_t *deleted_state =
    (hicn_face_prod_state_t *) _deleted_state;

  fib_prefix_t *prefix;

  // This cannot fail
  hicn_face_t *face = hicn_dpoi_get_from_idx (face_id);
  ASSERT (face);

  // Be sure we are deleting a producer face
  if (face->flags & HICN_FACE_FLAGS_APPFACE_PROD)
    {
      /* Remove the app state */
      ret = hicn_app_state_del (&face->nat_addr, face->randomized_port,
				face->sw_if, deleted_state);
      if (ret)
	{
	  vlib_cli_output (vlib_get_main (), "Error deleting app state",
			   get_error_string (ret));
	  goto end;
	}

      // Remove the prefix from the FIB
      HICN_DEBUG ("Calling hicn_route_disable from hicn_face_prod_del");
      prefix = &deleted_state->prefix;
      ret = hicn_route_disable (prefix);
      if (ret)
	{
	  vlib_cli_output (vlib_get_main (), "Error disabling route: %s",
			   get_error_string (ret));
	  goto end;
	}

      // Also remove prefix from main fib, as we are the owners of this prefix
      u32 fib_index = fib_table_find (prefix->fp_proto, 0);
      fib_table_entry_special_remove (fib_index, prefix, FIB_SOURCE_CLI);
      if (ret)
	{
	  vlib_cli_output (vlib_get_main (), "Error deleting app state: %s",
			   get_error_string (ret));
	  goto end;
	}
    }
  else
    {
      vlib_main_t *vm = vlib_get_main ();
      vlib_cli_output (vm, "APPFACE not found.",
		       get_error_string (HICN_ERROR_APPFACE_NOT_FOUND));
      ret = HICN_ERROR_APPFACE_NOT_FOUND;
    }

end:
  return ret;
}

u8 *
format_hicn_face_prod (u8 *s, va_list *args)
{
  CLIB_UNUSED (index_t index) = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  s = format (s, " (producer app)");

  return s;
}

VNET_FEATURE_INIT (hicn_prod_app_input_ip6, static) = {
  .arc_name = "ip6-local",
  .node_name = "hicn-face-prod-input",
  .runs_before = VNET_FEATURES ("hicn-data-input-ip6"),
};

VNET_FEATURE_INIT (hicn_prod_app_input_ip4, static) = {
  .arc_name = "ip4-local",
  .node_name = "hicn-face-prod-input",
  .runs_before = VNET_FEATURES ("hicn-data-input-ip4"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
