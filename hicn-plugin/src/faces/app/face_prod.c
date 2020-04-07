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
#include <vnet/interface_funcs.h>

#include "face_prod.h"
#include "address_mgr.h"
#include "../../infra.h"
#include "../../route.h"
#include "../../cache_policies/cs_lru.h"

hicn_face_prod_state_t *face_state_vec;

/* used to check if an interface is already in the vector */
u32 *face_state_pool;

static int
hicn_app_state_create (u32 swif, fib_prefix_t * prefix)
{
  /* Make sure that the pool is not empty */
  pool_validate_index (face_state_pool, 0);

  u32 *swif_app;
  u8 found = 0;
  /* *INDENT-OFF* */
  pool_foreach (swif_app, face_state_pool,{
      if (*swif_app == swif)
	{
	  found = 1;
	}
    }
  );
  /* *INDENT-ON* */


  if (found)
    return HICN_ERROR_APPFACE_ALREADY_ENABLED;


  /* Create the appif and store in the vector */
  vec_validate (face_state_vec, swif);
  clib_memcpy (&(face_state_vec[swif].prefix), prefix, sizeof (fib_prefix_t));

  /* Set as busy the element in the vector */
  pool_get (face_state_pool, swif_app);
  *swif_app = swif;

  int ret = HICN_ERROR_NONE;
  if (ip46_address_is_ip4 (&(prefix->fp_addr)))
    {
      ret =
	vnet_feature_enable_disable ("ip4-unicast", "hicn-face-prod-input",
				     swif, 1, 0, 0);
    }
  else
    {
      ret =
	vnet_feature_enable_disable ("ip6-unicast", "hicn-face-prod-input",
				     swif, 1, 0, 0);
    }

  return ret == 0 ? HICN_ERROR_NONE : HICN_ERROR_APPFACE_FEATURE;
}

static int
hicn_app_state_del (u32 swif)
{
  /* Make sure that the pool is not empty */
  pool_validate_index (face_state_pool, 0);

  u32 *temp;
  u32 *swif_app = NULL;
  u8 found = 0;
  fib_prefix_t *prefix;
  /* *INDENT-OFF* */
  pool_foreach (temp, face_state_pool,{
      if (*temp == swif)
	{
	  found = 1;
	  swif_app = temp;
	}
    }
  );
  /* *INDENT-ON* */

  if (!found)
    return HICN_ERROR_APPFACE_NOT_FOUND;

  prefix = &(face_state_vec[swif].prefix);

  int ret = HICN_ERROR_NONE;
  if (ip46_address_is_ip4 (&prefix->fp_addr))
    {
      ret =
	vnet_feature_enable_disable ("ip4-unicast", "hicn-face-prod-input",
				     swif, 0, 0, 0);
    }
  else
    {
      ret =
	vnet_feature_enable_disable ("ip6-unicast", "hicn-face-prod-input",
				     swif, 0, 0, 0);
    }

  pool_put (face_state_pool, swif_app);
  memset (&face_state_vec[swif], 0, sizeof (hicn_face_prod_state_t));

  return ret == 0 ? HICN_ERROR_NONE : HICN_ERROR_APPFACE_FEATURE;
}

int
hicn_face_prod_add (fib_prefix_t * prefix, u32 sw_if, u32 * cs_reserved,
		    ip46_address_t * prod_addr, hicn_face_id_t * faceid)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();

  hicn_main_t *hm = &hicn_main;

  ip46_address_t local_app_ip;
  CLIB_UNUSED(ip46_address_t remote_app_ip);
  u32 if_flags = 0;

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

  u8 *s0;
  s0 = format (0, "Prefix %U", format_fib_prefix, prefix);

  vlib_cli_output (vm, "Received request for %s, swif %d\n", s0, sw_if);

  if (ip46_address_is_zero (&prefix->fp_addr))
    {
      return HICN_ERROR_APPFACE_PROD_PREFIX_NULL;
    }
  /*
   * Check if a producer face is already existing for the same prefix
   * and sw_if
   */
  face = hicn_face_get (&(prefix->fp_addr), sw_if,
                            &hicn_face_hashtb);

  if (face != NULL)
    {
      if (!(face->flags & HICN_FACE_FLAGS_DELETED))
	return HICN_ERROR_FACE_ALREADY_CREATED;

      /*
       * Something went worng, a consumer face exists for the
       * producer's prefix.
       */
      /* It should never happens, this is a safety check. */
      if (face->flags & HICN_FACE_FLAGS_APPFACE_CONS)
	return HICN_ERROR_FACE_ALREADY_CREATED;

      /* If the face exists but is marked as deleted, undelete it */
      if (face->flags & HICN_FACE_FLAGS_DELETED)
	{
	  /*
	   * remove the deleted flag and retrieve the face
	   * local addr
	   */
	  face->flags &= HICN_FACE_FLAGS_DELETED;
	}
    }
  else
    {
      /* Otherwise create the face */
      if (ip46_address_is_ip4 (&prefix->fp_addr))
	{
	  /*
	   * Otherwise retrieve an ip address to assign as a
	   * local ip addr.
	   */
	  ip4_address_t local_app_ip4;
	  ip4_address_t remote_app_ip4;
	  get_two_ip4_addresses (&local_app_ip4, &remote_app_ip4);
	  ip4_add_del_interface_address (vm,
					 sw_if,
					 &local_app_ip4, 31, 0 /* is_del */ );
	  local_app_ip = to_ip46 ( /* isv6 */ 0, local_app_ip4.as_u8);
	  remote_app_ip = to_ip46 ( /* isv6 */ 0, remote_app_ip4.as_u8);
	}
      else
	{
	  ip6_address_t local_app_ip6;
	  ip6_address_t remote_app_ip6;
	  get_two_ip6_addresses (&local_app_ip6, &remote_app_ip6);
	  u8 *s0;
	  s0 = format (0, "%U", format_ip6_address, &local_app_ip6);

	  vlib_cli_output (vm, "Setting ip address %s\n", s0);

	  ip6_add_del_interface_address (vm,
					 sw_if,
					 &local_app_ip6, 127,
					 0 /* is_del */ );
	  local_app_ip = to_ip46 ( /* isv6 */ 1, local_app_ip6.as_u8);
	  remote_app_ip = to_ip46 ( /* isv6 */ 1, remote_app_ip6.as_u8);
	}
    }

  if (ret == HICN_ERROR_NONE)
    //    && hicn_face_prod_set_lru_max (*faceid, cs_reserved) == HICN_ERROR_NONE)
    {
      fib_route_path_t rpath = {0};
      fib_route_path_t * rpaths = NULL;

      if (ip46_address_is_ip4(&(prefix->fp_addr)))
        {
          ip4_address_t mask;
          ip4_preflen_to_mask (prefix->fp_len, &mask);
          prefix->fp_addr.ip4.as_u32 = prefix->fp_addr.ip4.as_u32 & mask.as_u32;
          prefix->fp_proto = FIB_PROTOCOL_IP4;

          rpath.frp_weight = 1;
          rpath.frp_sw_if_index = ~0;
          rpath.frp_addr.ip4.as_u32 = remote_app_ip.ip4.as_u32;
          rpath.frp_sw_if_index = sw_if;
          rpath.frp_proto = DPO_PROTO_IP4;

          vec_add1 (rpaths, rpath);
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

          rpath.frp_weight = 1;
          rpath.frp_sw_if_index = ~0;
          rpath.frp_addr.ip6.as_u64[0] = remote_app_ip.ip6.as_u64[0];
          rpath.frp_addr.ip6.as_u64[1] = remote_app_ip.ip6.as_u64[1];
          rpath.frp_sw_if_index = sw_if;
          rpath.frp_proto = DPO_PROTO_IP6;

          vec_add1 (rpaths, rpath);
        }

      u32 fib_index = fib_table_find (prefix->fp_proto, 0);
      fib_table_entry_path_add2 (fib_index,
                                 prefix,
                                 FIB_SOURCE_CLI,
                                 FIB_ENTRY_FLAG_NONE, rpaths);

      hicn_app_state_create (sw_if, prefix);
      hicn_route_enable(prefix);
    }

  face = hicn_face_get(&local_app_ip, sw_if, &hicn_face_hashtb);//HICN_FACE_FLAGS_APPFACE_PROD);

  *faceid = hicn_dpoi_get_index (face);

  face->flags |= HICN_FACE_FLAGS_APPFACE_PROD;

  hicn_face_unlock_with_id(*faceid);

  *prod_addr = local_app_ip;

  /* Cleanup in case of something went wrong. */
  if (ret)
    {
      hicn_app_state_del (sw_if);
    }
  return ret;
}

int
hicn_face_prod_del (hicn_face_id_t face_id)
{
  if (!hicn_dpoi_idx_is_valid (face_id))
    return HICN_ERROR_APPFACE_NOT_FOUND;

  hicn_face_t *face = hicn_dpoi_get_from_idx (face_id);

  if (face->flags & HICN_FACE_FLAGS_APPFACE_PROD)
    {
      /* Remove the face from the fib */
      hicn_route_disable(&(face_state_vec[face->sw_if].prefix));
      //hicn_route_del_nhop (&(face_state_vec[face->sw_if].prefix),
      //			   face_id);

      //int ret = hicn_face_del (face_id);
      return hicn_app_state_del (face->sw_if);
        //ret == HICN_ERROR_NONE ? hicn_app_state_del (face->sw_if) : ret;
    }
  else
    {
      return HICN_ERROR_APPFACE_NOT_FOUND;
    }

  return HICN_ERROR_NONE;
}

u8 *
format_hicn_face_prod (u8 * s, va_list * args)
{
  CLIB_UNUSED (index_t index) = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  s =
    format (s, " (producer)");

  return s;
}

/* *INDENT-OFF* */
VNET_FEATURE_INIT(hicn_prod_app_input_ip6, static)=
{
  .arc_name = "ip6-unicast",
  .node_name = "hicn-face-prod-input",
  .runs_before = VNET_FEATURES("ip6-inacl"),
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_FEATURE_INIT(hicn_prod_app_input_ip4, static)=
{
  .arc_name = "ip4-unicast",
  .node_name = "hicn-face-prod-input",
  .runs_before = VNET_FEATURES("ip4-inacl"),
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
