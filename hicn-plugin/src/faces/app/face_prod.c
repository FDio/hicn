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

#include "face_prod.h"
#include "address_mgr.h"
#include "../../infra.h"
#include "../../route.h"
#include "../../cache_policies/cs_lru.h"

hicn_face_prod_state_t *face_state_vec;

/* used to check if an interface is already in the vector */
u32 *face_state_pool;

static int
hicn_app_state_create (u32 swif, hicn_prefix_t * prefix)
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
  clib_memcpy (&(face_state_vec[swif].prefix), prefix,
	       sizeof (hicn_prefix_t));

  /* Set as busy the element in the vector */
  pool_get (face_state_pool, swif_app);
  *swif_app = swif;

  int ret = HICN_ERROR_NONE;
  if (ip46_address_is_ip4 (&(prefix->name)))
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
  ip46_address_t *prefix_addr;
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

  prefix_addr = &(face_state_vec[swif].prefix.name);
  if (!found)
    return HICN_ERROR_APPFACE_NOT_FOUND;

  int ret = HICN_ERROR_NONE;
  if (ip46_address_is_ip4 (prefix_addr))
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
hicn_face_prod_add (hicn_prefix_t * prefix, u32 sw_if, u32 * cs_reserved,
		    ip46_address_t * prod_addr, hicn_face_id_t * faceid)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();

  hicn_main_t *hm = &hicn_main;

  ip46_address_t app_ip;
  u32 if_flags = 0;

  if (!hm->is_enabled)
    {
      return HICN_ERROR_FWD_NOT_ENABLED;
    }
  int ret = HICN_ERROR_NONE;
  hicn_face_t *face = NULL;

  if_flags |= VNET_SW_INTERFACE_FLAG_ADMIN_UP;
  vnet_sw_interface_set_flags (vnm, sw_if, if_flags);

  if (ip46_address_is_zero (&prefix->name))
    {
      return HICN_ERROR_APPFACE_PROD_PREFIX_NULL;
    }
  /*
   * Check if a producer face is already existing for the same prefix
   * and sw_if
   */
  if (ip46_address_is_ip4 (&prefix->name))
    {
      face =
	hicn_face_ip4_get (&(prefix->name.ip4), sw_if,
			   &hicn_face_ip_remote_hashtb);
    }
  else
    {
      face =
	hicn_face_ip6_get (&(prefix->name.ip6), sw_if,
			   &hicn_face_ip_remote_hashtb);
      if (face != NULL)
	return HICN_ERROR_FACE_ALREADY_CREATED;
    }

  if (face != NULL)
    {
      if (!(face->shared.flags & HICN_FACE_FLAGS_DELETED))
	return HICN_ERROR_FACE_ALREADY_CREATED;

      /*
       * Something went worng, a consumer face exists for the
       * producer's prefix.
       */
      /* It should never happens, this is a safety check. */
      if (face->shared.flags & HICN_FACE_FLAGS_APPFACE_CONS)
	return HICN_ERROR_FACE_ALREADY_CREATED;

      /* If the face exists but is marked as deleted, undelete it */
      if (face->shared.flags & HICN_FACE_FLAGS_DELETED)
	{
	  /*
	   * remove the deleted flag and retrieve the face
	   * local addr
	   */
	  face->shared.flags &= HICN_FACE_FLAGS_DELETED;
	  hicn_face_prod_t *prod_face = (hicn_face_prod_t *) face->data;
	  app_ip = prod_face->ip_face.local_addr;
	}
    }
  else
    {
      /* Otherwise create the face */
      if (ip46_address_is_ip4 (&prefix->name))
	{
	  /*
	   * Otherwise retrieve an ip address to assign as a
	   * local ip addr.
	   */
	  ip4_address_t app_ip4 = get_ip4_address ();
	  ip4_add_del_interface_address (vm,
					 sw_if,
					 &app_ip4,
					 ADDR_MGR_IP4_CONS_LEN,
					 0 /* is_del */ );
	  app_ip = to_ip46 ( /* isv6 */ 0, app_ip4.as_u8);
	}
      else
	{
	  ip6_address_t app_ip6 = get_ip6_address ();
	  ip6_add_del_interface_address (vm,
					 sw_if,
					 &app_ip6,
					 ADDR_MGR_IP6_CONS_LEN,
					 0 /* is_del */ );
	  app_ip = to_ip46 ( /* isv6 */ 1, app_ip6.as_u8);
	}

      /*
       * Special case: the nh_addr in the face is the appif ip
       * address
       */
      ret = hicn_face_ip_add (&app_ip, &(prefix->name), sw_if, faceid);

      face = hicn_dpoi_get_from_idx (*faceid);

      face->shared.flags |= HICN_FACE_FLAGS_APPFACE_PROD;

      hicn_face_prod_t *prod_face = (hicn_face_prod_t *) face->data;

      /*
       * For the moment we keep them here although it would be good
       * to create a different face for appface
       */
      prod_face->policy_vft.hicn_cs_insert = hicn_cs_lru.hicn_cs_insert;
      prod_face->policy_vft.hicn_cs_update = hicn_cs_lru.hicn_cs_update;
      prod_face->policy_vft.hicn_cs_dequeue = hicn_cs_lru.hicn_cs_dequeue;
      prod_face->policy_vft.hicn_cs_delete_get =
	hicn_cs_lru.hicn_cs_delete_get;
      prod_face->policy_vft.hicn_cs_trim = hicn_cs_lru.hicn_cs_trim;

    }

  if (ret == HICN_ERROR_NONE
      && hicn_face_prod_set_lru_max (*faceid, cs_reserved) == HICN_ERROR_NONE)
    {
      hicn_app_state_create (sw_if, prefix);
      ret = hicn_route_add (faceid, 1, &(prefix->name), prefix->len);
    }

  *prod_addr = app_ip;

  /* Cleanup in case of something went wrong. */
  if (ret)
    {
      hicn_app_state_del (sw_if);

      if (*faceid != HICN_FACE_NULL)
	hicn_face_ip_del (*faceid);
    }
  return ret;
}

int
hicn_face_prod_del (hicn_face_id_t face_id)
{
  hicn_face_t *face = hicn_dpoi_get_from_idx (face_id);

  if (face->shared.flags & HICN_FACE_FLAGS_APPFACE_PROD)
    {
      hicn_face_prod_t *prod_face = (hicn_face_prod_t *) face->data;
      /* Free the CS reserved for the face */
      hicn_main.pitcs.pcs_app_max += prod_face->policy.max;
      hicn_main.pitcs.pcs_app_count -= prod_face->policy.max;
      prod_face->policy.max = 0;

      /* Remove the face from the fib */
      hicn_route_del_nhop (&(face_state_vec[face->shared.sw_if].prefix.name),
			   (face_state_vec[face->shared.sw_if].prefix.len),
			   face_id);

      int ret = hicn_face_ip_del (face_id);
      return ret ==
	HICN_ERROR_NONE ? hicn_app_state_del (face->shared.sw_if) : ret;
    }
  else
    {
      return HICN_ERROR_APPFACE_NOT_FOUND;
    }
}

int
hicn_face_prod_set_lru_max (hicn_face_id_t face_id, u32 * requested_size)
{
  int ret = HICN_ERROR_NONE;
  vlib_main_t *vm = vlib_get_main ();
  hicn_face_t *face;
  hicn_face_prod_t *face_prod;

  if (!hicn_infra_fwdr_initialized)
    {
      ret = HICN_ERROR_FWD_NOT_ENABLED;
      vlib_cli_output (vm, "hicn: %s\n", get_error_string (ret));
      return ret;
    }
  face = hicn_dpoi_get_from_idx (face_id);
  face_prod = (hicn_face_prod_t *) face->data;

  if (face == NULL)
    return HICN_ERROR_FACE_NOT_FOUND;

  if (*requested_size > HICN_PARAM_FACE_MAX_CS_RESERVED)
    *requested_size = HICN_PARAM_FACE_MAX_CS_RESERVED;

  uint32_t available =
    hicn_main.pitcs.pcs_app_max - hicn_main.pitcs.pcs_app_count;

  if (*requested_size > available)
    *requested_size = available;

  face_prod->policy.max = *requested_size;
  face_prod->policy.count = 0;
  face_prod->policy.head = face_prod->policy.tail = 0;

  hicn_main.pitcs.pcs_app_count += *requested_size;

  return ret;
}

u8 *
format_hicn_face_prod (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);
  hicn_face_t *face;
  hicn_face_prod_t *prod_face;

  face = hicn_dpoi_get_from_idx (index);
  prod_face = (hicn_face_prod_t *) face->data;

  s =
    format (s, " (producer face: CS size %d, data cached %d)",
	    prod_face->policy.max, prod_face->policy.count);

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
