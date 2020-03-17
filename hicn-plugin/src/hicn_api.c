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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ip/ip_format_fns.h>

#include "faces/ip/face_ip.h"
#include "faces/udp/face_udp.h"
#include "infra.h"
#include "parser.h"
#include "mgmt.h"
#include "strategy_dpo_manager.h"
#include "strategy_dpo_ctx.h"
#include "strategy.h"
#include "pg.h"
#include "error.h"
#include "faces/app/face_prod.h"
#include "faces/app/face_cons.h"
#include "route.h"

/* define message IDs */
#include <hicn/hicn.api_enum.h>
#include <hicn/hicn.api_types.h>

/* define generated endian-swappers */
#define vl_endianfun
#include <hicn/hicn_all_api_h.h>
#undef vl_endianfun

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/****** SUPPORTING FUNCTION DECLARATIONS ******/

/*
 * Convert a unix return code to a vnet_api return code. Currently stubby:
 * should have more cases.
 */
always_inline vnet_api_error_t
hicn_face_api_entry_params_serialize (hicn_face_id_t faceid,
				      vl_api_hicn_api_face_ip_params_get_reply_t
				      * reply);


/****************** API MESSAGE HANDLERS ******************/

/****** NODE ******/

static void
vl_api_hicn_api_node_params_set_t_handler (vl_api_hicn_api_node_params_set_t *
					   mp)
{
  vl_api_hicn_api_node_params_set_reply_t *rmp;
  int rv;

  hicn_main_t *sm = &hicn_main;

  int pit_max_size = clib_net_to_host_i32 (mp->pit_max_size);
  pit_max_size =
    pit_max_size == -1 ? HICN_PARAM_PIT_ENTRIES_DFLT : pit_max_size;

  f64 pit_max_lifetime_sec = mp->pit_max_lifetime_sec;
  pit_max_lifetime_sec =
    pit_max_lifetime_sec ==
    -1 ? HICN_PARAM_PIT_LIFETIME_DFLT_MAX_MS / SEC_MS : pit_max_lifetime_sec;

  int cs_max_size = clib_net_to_host_i32 (mp->cs_max_size);
  cs_max_size = cs_max_size == -1 ? HICN_PARAM_CS_ENTRIES_DFLT : cs_max_size;

  int cs_reserved_app = clib_net_to_host_i32 (mp->cs_reserved_app);
  cs_reserved_app = cs_reserved_app >= 0
    && cs_reserved_app < 100 ? cs_reserved_app : HICN_PARAM_CS_RESERVED_APP;

  rv = hicn_infra_plugin_enable_disable ((int) (mp->enable_disable),
					 pit_max_size,
					 pit_max_lifetime_sec,
					 cs_max_size, cs_reserved_app);

  REPLY_MACRO (VL_API_HICN_API_NODE_PARAMS_SET_REPLY /* , rmp, mp, rv */ );
}

static void
vl_api_hicn_api_node_params_get_t_handler (vl_api_hicn_api_node_params_get_t *
					   mp)
{
  vl_api_hicn_api_node_params_get_reply_t *rmp;
  int rv = HICN_ERROR_NONE;

  hicn_main_t *sm = &hicn_main;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_HICN_API_NODE_PARAMS_GET_REPLY, (
    {
      rmp->is_enabled = sm->is_enabled;
      rmp->feature_cs =	HICN_FEATURE_CS;
      rmp->pit_max_size = clib_host_to_net_u32 (hicn_infra_pit_size);
      rmp->pit_max_lifetime_sec	= ((f64) sm->pit_lifetime_max_ms) / SEC_MS;
      rmp->cs_max_size = clib_host_to_net_u32 (hicn_infra_cs_size);
      rmp->retval = clib_host_to_net_i32 (rv);
    }));
  /* *INDENT-ON* */
}

static void
vl_api_hicn_api_node_stats_get_t_handler (vl_api_hicn_api_node_stats_get_t *
					  mp)
{
  vl_api_hicn_api_node_stats_get_reply_t *rmp;
  int rv = HICN_ERROR_NONE;

  hicn_main_t *sm = &hicn_main;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_HICN_API_NODE_STATS_GET_REPLY, (
    {
      rv = hicn_mgmt_node_stats_get (rmp);
      rmp->retval =clib_host_to_net_i32 (rv);
    }));
  /* *INDENT-ON* */
}


/****** FACE *******/
static hicn_error_t
hicn_api_face_ip_add (vl_api_hicn_face_ip_t * mp, hicn_face_id_t * face_id)
{
  hicn_error_t rv = HICN_ERROR_NONE;

  vnet_main_t *vnm = vnet_get_main ();

  ip46_address_t local_addr;
  ip46_address_t remote_addr;
  ip_address_decode (&mp->local_addr, &local_addr);
  ip_address_decode (&mp->remote_addr, &remote_addr);

  u32 sw_if = clib_net_to_host_u32 (mp->swif);

  if (ip46_address_is_zero (&local_addr))
    {
      if (!vnet_sw_interface_is_valid (vnm, sw_if))
	{
	  rv = HICN_ERROR_UNSPECIFIED;
	}

      if ((rv == HICN_ERROR_NONE) && ip46_address_is_ip4 (&remote_addr))
	{
	  ip_interface_address_t *interface_address;
	  ip4_address_t *addr =
	    ip4_interface_address_matching_destination (&ip4_main,
							&remote_addr.ip4,
							sw_if,
							&interface_address);
	  if (addr == NULL)
	    addr = ip4_interface_first_address (&ip4_main,
						sw_if, &interface_address);

	  if (addr == NULL)
	    rv = HICN_ERROR_UNSPECIFIED;
	  else
	    ip46_address_set_ip4 (&local_addr, addr);
	}
      else
	{
	  ip_interface_address_t *interface_address;
	  ip6_interface_address_matching_destination (&ip6_main,
						      &remote_addr.ip6, sw_if,
						      &interface_address);
	  ip6_address_t *addr = NULL;
	  if (rv == HICN_ERROR_NONE && interface_address != NULL)
	    {
	      addr =
		(ip6_address_t *)
		ip_interface_address_get_address (&ip6_main.lookup_main,
						  interface_address);
	    }
	  else
	    {
	      addr = ip6_interface_first_address (&ip6_main, sw_if);
	    }

	  if (addr == NULL)
	    rv = HICN_ERROR_UNSPECIFIED;
	  else
	    ip46_address_set_ip6 (&local_addr, addr);
	}
    }

  if (rv == HICN_ERROR_NONE)
    rv = hicn_face_ip_add (&local_addr, &remote_addr, sw_if, face_id, 0);

  return rv;
}

static void
vl_api_hicn_api_face_ip_add_t_handler (vl_api_hicn_api_face_ip_add_t * mp)
{
  vl_api_hicn_api_face_ip_add_reply_t *rmp;
  hicn_error_t rv = HICN_ERROR_NONE;

  hicn_main_t *sm = &hicn_main;
  hicn_face_id_t face_id = HICN_FACE_NULL;
  rv = hicn_api_face_ip_add (&(mp->face), &face_id);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_HICN_API_FACE_IP_ADD_REPLY /* , rmp, mp, rv */ ,(
    {
      rmp->faceid = clib_host_to_net_u32 ((u32) face_id);
      rmp->retval = rv;
    }));
  /* *INDENT-ON* */
}

static void
vl_api_hicn_api_face_ip_del_t_handler (vl_api_hicn_api_face_ip_del_t * mp)
{
  vl_api_hicn_api_face_ip_del_reply_t *rmp;
  int rv = HICN_ERROR_FACE_NOT_FOUND;

  hicn_main_t *sm = &hicn_main;

  hicn_face_id_t faceid = clib_net_to_host_u32 (mp->faceid);
  if (hicn_dpoi_idx_is_valid (faceid))
    {
      rv = hicn_face_ip_del (faceid);
    }

  REPLY_MACRO (VL_API_HICN_API_FACE_IP_DEL_REPLY /* , rmp, mp, rv */ );

}

static void
  vl_api_hicn_api_face_ip_params_get_t_handler
  (vl_api_hicn_api_face_ip_params_get_t * mp)
{
  vl_api_hicn_api_face_ip_params_get_reply_t *rmp;
  int rv = 0;

  hicn_main_t *sm = &hicn_main;

  hicn_face_id_t faceid = clib_net_to_host_u32 (mp->faceid);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_HICN_API_FACE_IP_PARAMS_GET_REPLY, (
    {
      rv = hicn_face_api_entry_params_serialize(faceid, rmp);
      rmp->retval = clib_host_to_net_u32(rv);
    }));
  /* *INDENT-ON* */
}

static hicn_error_t
hicn_api_face_udp_add (vl_api_hicn_face_udp_t * mp, hicn_face_id_t * face_id)
{
  hicn_error_t rv = HICN_ERROR_NONE;

  ip46_address_t local_addr = ip46_address_initializer;
  ip46_address_t remote_addr = ip46_address_initializer;
  u16 lport;
  u16 rport;
  u32 sw_if;
  ip_address_decode (&mp->local_addr, &local_addr);
  ip_address_decode (&mp->remote_addr, &remote_addr);
  //Do not byteswap. We store ports in network order
  lport = mp->lport;
  rport = mp->rport;
  sw_if = clib_net_to_host_u32 (mp->swif);

  int input_is_ok = !ip46_address_is_zero (&local_addr)
    && !ip46_address_is_zero (&remote_addr)
    &&
    ((ip46_address_is_ip4 (&local_addr) && ip46_address_is_ip4 (&remote_addr))
     || (!ip46_address_is_ip4 (&local_addr)
	 && !ip46_address_is_ip4 (&remote_addr))) && lport != 0 && rport != 0;

  if (!input_is_ok)
    {
      rv = HICN_ERROR_UNSPECIFIED;
    }
  else
    {
      rv = hicn_face_udp_add (&local_addr,
			      &remote_addr, lport, rport, sw_if, face_id);
    }
  return rv;
}

static void
vl_api_hicn_api_face_add_t_handler (vl_api_hicn_api_face_add_t * mp)
{
  vl_api_hicn_api_face_add_reply_t *rmp;
  hicn_error_t rv = HICN_ERROR_NONE;

  hicn_main_t *sm = &hicn_main;
  hicn_face_id_t face_id;
  vl_api_hicn_face_type_t face_type = clib_net_to_host_u32 (mp->type);

  switch (face_type)
    {
    case IP_FACE:
      rv = hicn_api_face_ip_add (&(mp->face.ip), &face_id);
      break;
    case UDP_FACE:
      rv = hicn_api_face_udp_add (&(mp->face.udp), &face_id);
      break;
    default:
      rv = HICN_ERROR_UNSPECIFIED;
      break;
    }

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_HICN_API_FACE_ADD_REPLY /* , rmp, mp, rv */ ,(
    {
      rmp->faceid = clib_host_to_net_u32 ((u32) face_id);
      rmp->retval = clib_host_to_net_u32 (rv);
    }));
  /* *INDENT-ON* */
}

static void
vl_api_hicn_api_face_del_t_handler (vl_api_hicn_api_face_del_t * mp)
{
  vl_api_hicn_api_face_del_reply_t *rmp;
  int rv = HICN_ERROR_FACE_NOT_FOUND;

  hicn_main_t *sm = &hicn_main;

  hicn_face_id_t faceid = clib_net_to_host_u32 (mp->faceid);
  if (hicn_dpoi_idx_is_valid (faceid))
    {
      hicn_face_t *face = hicn_dpoi_get_from_idx (faceid);
      hicn_face_vft_t *vft = hicn_face_get_vft (face->shared.face_type);
      rv = vft->hicn_face_del (faceid);
    }

  REPLY_MACRO (VL_API_HICN_API_FACE_DEL_REPLY /* , rmp, mp, rv */ );
}

static void
send_face_ip_details (hicn_face_t * face, vl_api_hicn_face_ip_t * mp)
{
  vnet_main_t *vnm = vnet_get_main ();

  hicn_face_ip_t *face_ip = (hicn_face_ip_t *) face->data;
  ip_address_encode (&face_ip->local_addr, IP46_TYPE_ANY, &mp->local_addr);
  ip_address_encode (&face_ip->remote_addr, IP46_TYPE_ANY, &mp->remote_addr);
  mp->flags = clib_host_to_net_u32 (face->shared.flags);
  mp->swif = clib_net_to_host_u32 (face->shared.sw_if);
  vnet_sw_interface_t *sw_interface =
    vnet_get_sw_interface_or_null (vnm, face->shared.sw_if);
  u8 *sbuf = 0;
  if (sw_interface != NULL)
    {
      sbuf =
	format (0, "%U", format_vnet_sw_interface_name, vnm, sw_interface);
      strcpy ((char *) (mp->if_name), (char *) sbuf);
    }
}

static void
send_face_udp_details (hicn_face_t * face, vl_api_hicn_face_udp_t * mp)
{
  vnet_main_t *vnm = vnet_get_main ();
  hicn_face_udp_t *face_udp = (hicn_face_udp_t *) face->data;
  if (face_udp->hdrs.ip4.ip.ip_version_and_header_length == 0x45)
    {
      ip46_address_t src_addr = { 0 };
      ip46_address_t dst_addr = { 0 };
      ip46_address_set_ip4 (&src_addr, &(face_udp->hdrs.ip4.ip.src_address));
      ip46_address_set_ip4 (&dst_addr, &(face_udp->hdrs.ip4.ip.dst_address));

      ip_address_encode (&src_addr, IP46_TYPE_ANY, &(mp->local_addr));
      ip_address_encode (&dst_addr, IP46_TYPE_ANY, &(mp->remote_addr));
      //Do not swap, they are already in network order
      mp->lport = face_udp->hdrs.ip4.udp.src_port;
      mp->rport = face_udp->hdrs.ip4.udp.dst_port;
    }
  else
    {
      ip46_address_t src_addr = { 0 };
      ip46_address_t dst_addr = { 0 };
      ip46_address_set_ip6 (&src_addr, &(face_udp->hdrs.ip6.ip.src_address));
      ip46_address_set_ip6 (&dst_addr, &(face_udp->hdrs.ip6.ip.dst_address));

      ip_address_encode (&src_addr, IP46_TYPE_ANY, &(mp->local_addr));
      ip_address_encode (&dst_addr, IP46_TYPE_ANY, &(mp->remote_addr));
      //Do not swap, they are already in network order
      mp->lport = face_udp->hdrs.ip6.udp.src_port;
      mp->rport = face_udp->hdrs.ip6.udp.dst_port;
    }
  mp->flags = clib_host_to_net_u32 (face->shared.flags);
  mp->swif = clib_net_to_host_u32 (face->shared.sw_if);
  vnet_sw_interface_t *sw_interface =
    vnet_get_sw_interface_or_null (vnm, face->shared.sw_if);
  u8 *sbuf = 0;
  if (sw_interface != NULL)
    {
      sbuf =
	format (0, "%U", format_vnet_sw_interface_name, vnm, sw_interface);
      strcpy ((char *) (mp->if_name), (char *) sbuf);
    }
}

static void
send_faces_details (vl_api_registration_t * reg,
		    hicn_face_t * face, u32 context)
{
  vl_api_hicn_api_faces_details_t *mp;
  hicn_main_t *hm = &hicn_main;
  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->faceid = clib_host_to_net_u32 (hicn_dpoi_get_index (face));
  mp->_vl_msg_id = htons (VL_API_HICN_API_FACES_DETAILS + hm->msg_id_base);
  mp->context = context;

  if (face->shared.face_type == hicn_face_ip_type)
    {
      mp->type = clib_host_to_net_u32 (IP_FACE);
      send_face_ip_details (face, &(mp->face.ip));
    }
  else if (face->shared.face_type == hicn_face_udp_type)
    {
      mp->type = clib_host_to_net_u32 (UDP_FACE);
      send_face_udp_details (face, &(mp->face.udp));
    }


  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_hicn_api_faces_dump_t_handler (vl_api_hicn_api_faces_dump_t * mp)
{
  hicn_face_t *face;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (face, hicn_dpoi_face_pool,
                ({
                  send_faces_details (reg, face, mp->context);
                }));
  /* *INDENT-ON* */
}

static void
vl_api_hicn_api_face_get_t_handler (vl_api_hicn_api_face_get_t * mp)
{
  vl_api_hicn_api_face_get_reply_t *rmp;
  int rv = 0;

  hicn_main_t *sm = &hicn_main;

  hicn_face_id_t faceid = clib_net_to_host_u32 (mp->faceid);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_HICN_API_FACE_GET_REPLY, (
    {
      rv = hicn_dpoi_idx_is_valid(faceid);
      if (rv)
        {
          hicn_face_t * face = hicn_dpoi_get_from_idx(faceid);
          if (face->shared.face_type ==  hicn_face_ip_type)
            {
              rmp->type = IP_FACE;
              send_face_ip_details(face, &(rmp->face.ip));
            }
          else if (face->shared.face_type ==  hicn_face_udp_type)
            {
              rmp->type = UDP_FACE;
              send_face_udp_details(face, &(rmp->face.udp));
            }
          rv = HICN_ERROR_NONE;
        }
      else
        {
          rv = HICN_ERROR_FACE_NOT_FOUND;
        }
      rmp->retval = clib_host_to_net_u32(rv);
    }));
  /* *INDENT-ON* */
}

static void
send_face_stats_details (vl_api_registration_t * reg,
			 hicn_face_t * face, u32 context)
{
  vl_api_hicn_api_face_stats_details_t *mp;
  hicn_main_t *hm = &hicn_main;
  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id =
    htons (VL_API_HICN_API_FACE_STATS_DETAILS + hm->msg_id_base);
  mp->context = context;

  mp->faceid = htonl (hicn_dpoi_get_index (face));
  vlib_counter_t v;
  vlib_get_combined_counter (&counters
			     [hicn_dpoi_get_index (face) * HICN_N_COUNTER],
			     HICN_FACE_COUNTERS_INTEREST_RX, &v);
  mp->irx_packets = clib_net_to_host_u64 (v.packets);
  mp->irx_bytes = clib_net_to_host_u64 (v.bytes);

  vlib_get_combined_counter (&counters
			     [hicn_dpoi_get_index (face) * HICN_N_COUNTER],
			     HICN_FACE_COUNTERS_INTEREST_TX, &v);
  mp->itx_packets = clib_net_to_host_u64 (v.packets);
  mp->itx_bytes = clib_net_to_host_u64 (v.bytes);

  vlib_get_combined_counter (&counters
			     [hicn_dpoi_get_index (face) * HICN_N_COUNTER],
			     HICN_FACE_COUNTERS_DATA_RX, &v);
  mp->drx_packets = clib_net_to_host_u64 (v.packets);
  mp->drx_bytes = clib_net_to_host_u64 (v.bytes);

  vlib_get_combined_counter (&counters
			     [hicn_dpoi_get_index (face) * HICN_N_COUNTER],
			     HICN_FACE_COUNTERS_DATA_TX, &v);
  mp->dtx_packets = clib_net_to_host_u64 (v.packets);
  mp->dtx_bytes = clib_net_to_host_u64 (v.bytes);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
  vl_api_hicn_api_face_stats_dump_t_handler
  (vl_api_hicn_api_face_stats_dump_t * mp)
{
  hicn_face_t *face;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (face, hicn_dpoi_face_pool,
                ({
                  send_face_stats_details (reg, face, mp->context);
                }));
  /* *INDENT-ON* */
}


/****** ROUTE *******/

static void
vl_api_hicn_api_route_nhops_add_t_handler (vl_api_hicn_api_route_nhops_add_t
					   * mp)
{
  vl_api_hicn_api_route_nhops_add_reply_t *rmp;
  int rv = HICN_ERROR_NONE;
  hicn_face_id_t face_ids[HICN_PARAM_FIB_ENTRY_NHOPS_MAX];

  hicn_main_t *sm = &hicn_main;

  fib_prefix_t prefix;
  ip_prefix_decode (&mp->prefix, &prefix);

  u8 n_faces = mp->n_faces;

  for (int i = 0; i < HICN_PARAM_FIB_ENTRY_NHOPS_MAX; i++)
    {
      face_ids[i] = clib_net_to_host_u32 (mp->face_ids[i]);
    }

  if ((face_ids == NULL) || (n_faces > HICN_PARAM_FIB_ENTRY_NHOPS_MAX))
    {
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
    }
  if (rv == HICN_ERROR_NONE)
    {
      rv = hicn_route_add (face_ids, n_faces, &prefix);

      if (rv == HICN_ERROR_ROUTE_ALREADY_EXISTS)
	{
	  rv = hicn_route_add_nhops (face_ids, n_faces, &prefix);
	}
    }
  REPLY_MACRO (VL_API_HICN_API_ROUTE_NHOPS_ADD_REPLY /* , rmp, mp, rv */ );
}


static void vl_api_hicn_api_route_del_t_handler
  (vl_api_hicn_api_route_del_t * mp)
{
  vl_api_hicn_api_route_del_reply_t *rmp;
  int rv = HICN_ERROR_NONE;

  hicn_main_t *sm = &hicn_main;

  fib_prefix_t prefix;
  ip_prefix_decode (&mp->prefix, &prefix);

  rv = hicn_route_del (&prefix);

  REPLY_MACRO (VL_API_HICN_API_ROUTE_DEL_REPLY /* , rmp, mp, rv */ );
}

static void vl_api_hicn_api_route_nhop_del_t_handler
  (vl_api_hicn_api_route_nhop_del_t * mp)
{
  vl_api_hicn_api_route_nhop_del_reply_t *rmp;
  int rv = HICN_ERROR_NONE;

  hicn_main_t *sm = &hicn_main;

  fib_prefix_t prefix;
  ip_prefix_decode (&mp->prefix, &prefix);
  hicn_face_id_t faceid = clib_net_to_host_u32 (mp->faceid);


  rv = hicn_route_del_nhop (&prefix, faceid);

  REPLY_MACRO (VL_API_HICN_API_ROUTE_NHOP_DEL_REPLY /* , rmp, mp, rv */ );
}

static void vl_api_hicn_api_route_get_t_handler
  (vl_api_hicn_api_route_get_t * mp)
{
  vl_api_hicn_api_route_get_reply_t *rmp;
  int rv = HICN_ERROR_NONE;

  hicn_main_t *sm = &hicn_main;

  fib_prefix_t prefix;
  ip_prefix_decode (&mp->prefix, &prefix);
  const dpo_id_t *hicn_dpo_id;
  hicn_dpo_ctx_t *hicn_dpo_ctx;
  u32 fib_index;

  rv = hicn_route_get_dpo (&prefix, &hicn_dpo_id, &fib_index);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_HICN_API_ROUTE_GET_REPLY, (
    {
      if (rv == HICN_ERROR_NONE)
	{
	  hicn_dpo_ctx = hicn_strategy_dpo_ctx_get(hicn_dpo_id->dpoi_index);
	  for (int i = 0; hicn_dpo_ctx != NULL && i < hicn_dpo_ctx->entry_count; i++)
	    {
	      if (dpo_id_is_valid(&hicn_dpo_ctx->next_hops[i]))
		{
		  rmp->faceids[i] =((dpo_id_t *) &hicn_dpo_ctx->next_hops[i])->dpoi_index;}
	    }
	  rmp->strategy_id = clib_host_to_net_u32(hicn_dpo_get_vft_id(hicn_dpo_id));}
    }));
  /* *INDENT-ON* */
}

static void
send_route_details (vl_api_registration_t * reg,
		    const fib_prefix_t * pfx, u32 context)
{
  vl_api_hicn_api_routes_details_t *mp;
  hicn_main_t *hm = &hicn_main;
  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_HICN_API_ROUTES_DETAILS + hm->msg_id_base);
  mp->context = context;

  ip_prefix_encode (pfx, &mp->prefix);
  mp->nfaces = 0;

  const dpo_id_t *hicn_dpo_id;
  hicn_dpo_ctx_t *hicn_dpo_ctx;
  u32 fib_index;

  int rv = hicn_route_get_dpo (pfx, &hicn_dpo_id, &fib_index);

  if (rv == HICN_ERROR_NONE)
    {
      hicn_dpo_ctx = hicn_strategy_dpo_ctx_get (hicn_dpo_id->dpoi_index);
      for (int i = 0; hicn_dpo_ctx != NULL && i < hicn_dpo_ctx->entry_count;
	   i++)
	{
	  if (dpo_id_is_valid (&hicn_dpo_ctx->next_hops[i]))
	    {
	      mp->faceids[i] =
		clib_host_to_net_u32 (((dpo_id_t *) &
				       hicn_dpo_ctx->
				       next_hops[i])->dpoi_index);
	      mp->nfaces++;
	    }
	}
      mp->strategy_id =
	clib_host_to_net_u32 (hicn_dpo_get_vft_id (hicn_dpo_id));
    }

  vl_api_send_msg (reg, (u8 *) mp);
}

typedef struct vl_api_hicn_api_route_dump_walk_ctx_t_
{
  fib_node_index_t *feis;
} vl_api_hicn_api_route_dump_walk_ctx_t;

static fib_table_walk_rc_t
vl_api_hicn_api_route_dump_walk (fib_node_index_t fei, void *arg)
{
  vl_api_hicn_api_route_dump_walk_ctx_t *ctx = arg;
  int found = 0;
  const dpo_id_t *former_dpo_id;

  /* Route already existing. We need to update the dpo. */
  const dpo_id_t *load_balance_dpo_id =
    fib_entry_contribute_ip_forwarding (fei);

  /* The dpo is not a load balance dpo as expected */
  if (load_balance_dpo_id->dpoi_type == DPO_LOAD_BALANCE)
    {
      /* former_dpo_id is a load_balance dpo */
      load_balance_t *lb = load_balance_get (load_balance_dpo_id->dpoi_index);

      /* FIB entry exists but there is no hicn dpo. */
      for (int i = 0; i < lb->lb_n_buckets && !found; i++)
	{
	  former_dpo_id = load_balance_get_bucket_i (lb, i);

	  if (dpo_is_hicn (former_dpo_id))
	    {
	      vec_add1 (ctx->feis, fei);
	    }
	}
    }

  return (FIB_TABLE_WALK_CONTINUE);
}

static void
vl_api_hicn_api_routes_dump_t_handler (vl_api_hicn_api_routes_dump_t * mp)
{
  vl_api_registration_t *reg;
  fib_table_t *fib_table;
  ip4_main_t *im = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  fib_node_index_t *lfeip;
  const fib_prefix_t *pfx;
  vl_api_hicn_api_route_dump_walk_ctx_t ctx = {
    .feis = NULL,
  };

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pool_foreach (fib_table, im->fibs, (
				       {
				       fib_table_walk (fib_table->ft_index,
						       FIB_PROTOCOL_IP4,
						       vl_api_hicn_api_route_dump_walk,
						       &ctx);}
		));

  pool_foreach (fib_table, im6->fibs, (
					{
					fib_table_walk (fib_table->ft_index,
							FIB_PROTOCOL_IP6,
							vl_api_hicn_api_route_dump_walk,
							&ctx);}
		));

  vec_foreach (lfeip, ctx.feis)
  {
    pfx = fib_entry_get_prefix (*lfeip);
    send_route_details (reg, pfx, mp->context);
  }

  vec_free (ctx.feis);

}

static void vl_api_hicn_api_strategies_get_t_handler
  (vl_api_hicn_api_strategies_get_t * mp)
{
  vl_api_hicn_api_strategies_get_reply_t *rmp;
  int rv = HICN_ERROR_NONE;

  hicn_main_t *sm = &hicn_main;

  int n_strategies = hicn_strategy_get_all_available ();

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_HICN_API_STRATEGIES_GET_REPLY/* , rmp, mp, rv */ ,(
    {
      int j = 0;
      for (u32 i = 0; i < (u32) n_strategies; i++)
	{
	  if (hicn_dpo_strategy_id_is_valid (i) == HICN_ERROR_NONE)
	    {
	      rmp->strategy_id[j] = clib_host_to_net_u32 (i); j++;}
	}
      rmp->n_strategies = n_strategies;
    }));
  /* *INDENT-ON* */
}

static void vl_api_hicn_api_strategy_get_t_handler
  (vl_api_hicn_api_strategy_get_t * mp)
{
  vl_api_hicn_api_strategy_get_reply_t *rmp;
  int rv = HICN_ERROR_NONE;

  hicn_main_t *sm = &hicn_main;

  u32 strategy_id = clib_net_to_host_u32 (mp->strategy_id);
  rv = hicn_dpo_strategy_id_is_valid (strategy_id);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_HICN_API_STRATEGY_GET_REPLY /* , rmp, mp, rv */ ,(
    {
      if (rv == HICN_ERROR_NONE)
	{
	  const hicn_strategy_vft_t * hicn_strategy_vft =
	    hicn_dpo_get_strategy_vft (strategy_id);
	  hicn_strategy_vft->hicn_format_strategy (rmp->description, 0);}
    }));
  /* *INDENT-ON* */
}

/************* APP FACE ****************/

static void vl_api_hicn_api_register_prod_app_t_handler
  (vl_api_hicn_api_register_prod_app_t * mp)
{
  vl_api_hicn_api_register_prod_app_reply_t *rmp;
  int rv = HICN_ERROR_NONE;

  hicn_main_t *sm = &hicn_main;

  fib_prefix_t prefix;
  ip_prefix_decode (&mp->prefix, &prefix);
  u32 swif = clib_net_to_host_u32 (mp->swif);
  u32 cs_reserved = clib_net_to_host_u32 (mp->cs_reserved);
  u32 faceid;

  ip46_address_t prod_addr;
  ip46_address_reset (&prod_addr);
  rv = hicn_face_prod_add (&prefix, swif, &cs_reserved, &prod_addr, &faceid);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_HICN_API_REGISTER_PROD_APP_REPLY, (
    {
      ip_address_encode(&prod_addr, IP46_TYPE_ANY, &rmp->prod_addr);
      rmp->cs_reserved = clib_net_to_host_u32(cs_reserved);
      rmp->faceid = clib_net_to_host_u32(faceid);
    }));
  /* *INDENT-ON* */
}

static void
vl_api_hicn_api_face_prod_del_t_handler (vl_api_hicn_api_face_prod_del_t * mp)
{
  vl_api_hicn_api_face_prod_del_reply_t *rmp;
  int rv = HICN_ERROR_FACE_NOT_FOUND;

  hicn_main_t *sm = &hicn_main;

  hicn_face_id_t faceid = clib_net_to_host_u32 (mp->faceid);
  rv = hicn_face_prod_del (faceid);

  REPLY_MACRO (VL_API_HICN_API_FACE_PROD_DEL_REPLY /* , rmp, mp, rv */ );
}

static void vl_api_hicn_api_register_cons_app_t_handler
  (vl_api_hicn_api_register_cons_app_t * mp)
{
  vl_api_hicn_api_register_cons_app_reply_t *rmp;
  int rv = HICN_ERROR_NONE;

  hicn_main_t *sm = &hicn_main;
  ip46_address_t src_addr4 = ip46_address_initializer;
  ip46_address_t src_addr6 = ip46_address_initializer;

  u32 swif = clib_net_to_host_u32 (mp->swif);
  u32 faceid1;
  u32 faceid2;

  rv =
    hicn_face_cons_add (&src_addr4.ip4, &src_addr6.ip6, swif, &faceid1,
			&faceid2);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_HICN_API_REGISTER_CONS_APP_REPLY, (
    {
      ip_address_encode(&src_addr4, IP46_TYPE_ANY, &rmp->src_addr4);
      ip_address_encode(&src_addr6, IP46_TYPE_ANY, &rmp->src_addr6);
      rmp->faceid1 = clib_net_to_host_u32(faceid1);
      rmp->faceid2 = clib_net_to_host_u32(faceid2);
    }));
  /* *INDENT-ON* */
}

static void
vl_api_hicn_api_face_cons_del_t_handler (vl_api_hicn_api_face_cons_del_t * mp)
{
  vl_api_hicn_api_face_cons_del_reply_t *rmp;
  int rv = HICN_ERROR_FACE_NOT_FOUND;

  hicn_main_t *sm = &hicn_main;

  hicn_face_id_t faceid = clib_net_to_host_u32 (mp->faceid);
  rv = hicn_face_cons_del (faceid);

  REPLY_MACRO (VL_API_HICN_API_FACE_CONS_DEL_REPLY /* , rmp, mp, rv */ );
}


/************************************************************************************/

#include <hicn/hicn.api.c>

/* Set up the API message handling tables */
clib_error_t *
hicn_api_plugin_hookup (vlib_main_t * vm)
{
  hicn_main_t *hm = &hicn_main;

  hm->msg_id_base = setup_message_id_table ();
  return 0;
}



/******************* SUPPORTING FUNCTIONS  *******************/

/*
 * Binary serialization for get face configuration API. for the moment
 * assuming only ip faces here. To be completed with othet types of faces
 */
vnet_api_error_t
hicn_face_api_entry_params_serialize (hicn_face_id_t faceid,
				      vl_api_hicn_api_face_ip_params_get_reply_t
				      * reply)
{
  int rv = HICN_ERROR_NONE;

  if (!reply)
    {
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
      goto done;
    }
  hicn_face_t *face = hicn_dpoi_get_from_idx (faceid);

  if (face != NULL && face->shared.face_type == hicn_face_ip_type)
    {
      hicn_face_ip_t *face_ip = (hicn_face_ip_t *) face->data;
      ip_address_encode (&face_ip->local_addr, IP46_TYPE_ANY,
			 &reply->local_addr);
      ip_address_encode (&face_ip->remote_addr, IP46_TYPE_ANY,
			 &reply->remote_addr);
      reply->swif = clib_host_to_net_u32 (face->shared.sw_if);
      reply->flags = clib_host_to_net_u32 (face->shared.flags);
      reply->faceid = clib_host_to_net_u32 (faceid);
    }
  else
    rv = HICN_ERROR_FACE_IP_ADJ_NOT_FOUND;

done:
  return (rv);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
