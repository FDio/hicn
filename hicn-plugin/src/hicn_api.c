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

#include "hicn.h"
#include "faces/ip/face_ip.h"
#include "infra.h"
#include "parser.h"
#include "mgmt.h"
#include "strategy_dpo_manager.h"
#include "strategy_dpo_ctx.h"
#include "strategy.h"
#include "pg.h"
#include "error.h"
#include "punt.h"
#include "faces/app/face_prod.h"
#include "faces/app/face_cons.h"
#include "route.h"

/* define message IDs */
#include <hicn/hicn_msg_enum.h>

/* define generated endian-swappers */
#define vl_endianfun
#include <hicn/hicn_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <hicn/hicn_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n, v) static u32 api_version=(v);
#include <hicn/hicn_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/****** List of message types that this plugin understands ******/

#define foreach_hicn_plugin_api_msg                                 \
  _(HICN_API_NODE_PARAMS_SET, hicn_api_node_params_set)             \
  _(HICN_API_NODE_PARAMS_GET, hicn_api_node_params_get)             \
  _(HICN_API_NODE_STATS_GET, hicn_api_node_stats_get)               \
  _(HICN_API_FACE_IP_ADD, hicn_api_face_ip_add)                     \
  _(HICN_API_FACE_IP_DEL, hicn_api_face_ip_del)                     \
  _(HICN_API_FACE_IP_PARAMS_GET, hicn_api_face_ip_params_get)       \
  _(HICN_API_ROUTE_GET, hicn_api_route_get)                         \
  _(HICN_API_ROUTE_NHOPS_ADD, hicn_api_route_nhops_add)             \
  _(HICN_API_ROUTE_DEL, hicn_api_route_del)                         \
  _(HICN_API_ROUTE_NHOP_DEL, hicn_api_route_nhop_del)               \
  _(HICN_API_STRATEGIES_GET, hicn_api_strategies_get)               \
  _(HICN_API_STRATEGY_GET, hicn_api_strategy_get)                   \
  _(HICN_API_PUNTING_ADD, hicn_api_punting_add)                     \
  _(HICN_API_PUNTING_DEL, hicn_api_punting_del)                     \
  _(HICN_API_REGISTER_PROD_APP, hicn_api_register_prod_app)         \
  _(HICN_API_REGISTER_CONS_APP, hicn_api_register_cons_app)


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
  pit_max_size = pit_max_size == -1? HICN_PARAM_PIT_ENTRIES_DFLT : pit_max_size;

  f64 pit_dflt_lifetime_sec = mp->pit_dflt_lifetime_sec;
  pit_dflt_lifetime_sec = pit_dflt_lifetime_sec == -1? HICN_PARAM_PIT_LIFETIME_DFLT_DFLT_MS : pit_dflt_lifetime_sec;

  f64 pit_min_lifetime_sec = mp->pit_min_lifetime_sec;
  pit_min_lifetime_sec = pit_min_lifetime_sec == -1? HICN_PARAM_PIT_LIFETIME_MIN_DFLT_MS : pit_min_lifetime_sec;

  f64 pit_max_lifetime_sec = mp->pit_max_lifetime_sec;
  pit_max_lifetime_sec = pit_max_lifetime_sec == -1? HICN_PARAM_PIT_LIFETIME_DFLT_DFLT_MS : pit_max_lifetime_sec;

  int cs_max_size = clib_net_to_host_i32 (mp->cs_max_size);
  cs_max_size = cs_max_size == -1? HICN_PARAM_CS_ENTRIES_DFLT : cs_max_size;

  int cs_reserved_app = clib_net_to_host_i32 (mp->cs_reserved_app);
  cs_reserved_app = cs_reserved_app >= 0
    && cs_reserved_app < 100 ? cs_reserved_app : HICN_PARAM_CS_RESERVED_APP;

  rv = hicn_infra_plugin_enable_disable ((int) (mp->enable_disable),
					 pit_max_size,
					 pit_dflt_lifetime_sec,
					 pit_min_lifetime_sec,
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
      rmp->pit_dflt_lifetime_sec = ((f64) sm->pit_lifetime_dflt_ms) / SEC_MS;
      rmp->pit_min_lifetime_sec	= ((f64) sm->pit_lifetime_min_ms) / SEC_MS;
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

static void
vl_api_hicn_api_face_ip_add_t_handler (vl_api_hicn_api_face_ip_add_t * mp)
{
  vl_api_hicn_api_face_ip_add_reply_t *rmp;
  int rv;

  hicn_main_t *sm = &hicn_main;

  hicn_face_id_t faceid = HICN_FACE_NULL;
  ip46_address_t nh_addr;
  nh_addr.as_u64[0] = clib_net_to_host_u64 (((u64 *) (&mp->nh_addr))[0]);
  nh_addr.as_u64[1] = clib_net_to_host_u64 (((u64 *) (&mp->nh_addr))[1]);

  u32 swif = clib_net_to_host_u32 (mp->swif);
  rv = hicn_face_ip_add (&nh_addr, NULL, swif, &faceid);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_HICN_API_FACE_IP_ADD_REPLY /* , rmp, mp, rv */ ,(
    {
      rmp->faceid = clib_host_to_net_u16 ((u16) faceid);
    }));
  /* *INDENT-ON* */
}

static void
vl_api_hicn_api_face_ip_del_t_handler (vl_api_hicn_api_face_ip_del_t * mp)
{
  vl_api_hicn_api_face_ip_del_reply_t *rmp;
  int rv = HICN_ERROR_NONE;

  hicn_main_t *sm = &hicn_main;

  hicn_face_id_t faceid = clib_net_to_host_u16 (mp->faceid);
  rv = hicn_face_del (faceid);

  REPLY_MACRO (VL_API_HICN_API_FACE_IP_DEL_REPLY /* , rmp, mp, rv */ );

}

static void
  vl_api_hicn_api_face_ip_params_get_t_handler
  (vl_api_hicn_api_face_ip_params_get_t * mp)
{
  vl_api_hicn_api_face_ip_params_get_reply_t *rmp;
  int rv = 0;

  hicn_main_t *sm = &hicn_main;

  hicn_face_id_t faceid = clib_net_to_host_u16 (mp->faceid);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_HICN_API_FACE_IP_PARAMS_GET_REPLY, (
    {
      rv = hicn_face_api_entry_params_serialize(faceid, rmp);
      rmp->retval = clib_host_to_net_u32(rv);
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

  ip46_address_t prefix;
  prefix.as_u64[0] = clib_net_to_host_u64 (((u64 *) (&mp->prefix))[0]);
  prefix.as_u64[1] = clib_net_to_host_u64 (((u64 *) (&mp->prefix))[1]);

  u8 len = mp->len;
  u8 n_faces = mp->n_faces;

  for (int i = 0; i < HICN_PARAM_FIB_ENTRY_NHOPS_MAX; i++)
    {
      face_ids[i] = clib_net_to_host_u16 (mp->face_ids[i]);
    }

  if ((face_ids == NULL) || (n_faces > HICN_PARAM_FIB_ENTRY_NHOPS_MAX))
    {
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
    }
  if (rv == HICN_ERROR_NONE)
    {
      rv = hicn_route_add (face_ids, n_faces, &prefix, len);

      if (rv == HICN_ERROR_ROUTE_ALREADY_EXISTS)
	{
	  rv = hicn_route_add_nhops (face_ids, n_faces, &prefix, len);
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

  ip46_address_t prefix;
  prefix.as_u64[0] = clib_net_to_host_u64 (((u64 *) (&mp->prefix))[0]);
  prefix.as_u64[1] = clib_net_to_host_u64 (((u64 *) (&mp->prefix))[1]);
  u8 len = mp->len;

  rv = hicn_route_del (&prefix, len);

  REPLY_MACRO (VL_API_HICN_API_ROUTE_DEL_REPLY /* , rmp, mp, rv */ );
}

static void vl_api_hicn_api_route_nhop_del_t_handler
  (vl_api_hicn_api_route_nhop_del_t * mp)
{
  vl_api_hicn_api_route_nhop_del_reply_t *rmp;
  int rv = HICN_ERROR_NONE;

  hicn_main_t *sm = &hicn_main;

  ip46_address_t prefix;
  prefix.as_u64[0] = clib_net_to_host_u64 (((u64 *) (&mp->prefix))[0]);
  prefix.as_u64[1] = clib_net_to_host_u64 (((u64 *) (&mp->prefix))[1]);
  u8 len = mp->len;
  hicn_face_id_t faceid = clib_net_to_host_u32 (mp->faceid);


  rv = hicn_route_del_nhop (&prefix, len, faceid);

  REPLY_MACRO (VL_API_HICN_API_ROUTE_NHOP_DEL_REPLY /* , rmp, mp, rv */ );
}

static void vl_api_hicn_api_route_get_t_handler
  (vl_api_hicn_api_route_get_t * mp)
{
  vl_api_hicn_api_route_get_reply_t *rmp;
  int rv = HICN_ERROR_NONE;

  hicn_main_t *sm = &hicn_main;

  ip46_address_t prefix;
  prefix.as_u64[0] = clib_net_to_host_u64 (((u64 *) (&mp->prefix))[0]);
  prefix.as_u64[1] = clib_net_to_host_u64 (((u64 *) (&mp->prefix))[1]);
  u8 len = mp->len;
  const dpo_id_t *hicn_dpo_id;
  const hicn_dpo_vft_t *hicn_dpo_vft;
  hicn_dpo_ctx_t *hicn_dpo_ctx;
  u32 fib_index;

  rv = hicn_route_get_dpo (&prefix, len, &hicn_dpo_id, &fib_index);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_HICN_API_ROUTE_GET_REPLY, (
    {
      if (rv == HICN_ERROR_NONE)
	{
	  hicn_dpo_vft = hicn_dpo_get_vft(hicn_dpo_id->dpoi_index);
	  hicn_dpo_ctx = hicn_dpo_vft->hicn_dpo_get_ctx(hicn_dpo_id->dpoi_index);
	  for (int i = 0; i < hicn_dpo_ctx->entry_count; i++)
	    {
	      if (dpo_id_is_valid(&hicn_dpo_ctx->next_hops[i]))
		{
		  rmp->faceids[i] =((dpo_id_t *) &hicn_dpo_ctx->next_hops[i])->dpoi_index;}
	    }
	  rmp->strategy_id = clib_host_to_net_u32(hicn_dpo_get_vft_id(hicn_dpo_id));}
    }));
  /* *INDENT-ON* */
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
	  const hicn_dpo_vft_t * hicn_dpo_vft =
	    hicn_dpo_get_vft (strategy_id);
	  hicn_dpo_vft->format_hicn_dpo (rmp->description, 0);}
    }));
  /* *INDENT-ON* */
}

/****** PUNTING *******/

static void vl_api_hicn_api_punting_add_t_handler
  (vl_api_hicn_api_punting_add_t * mp)
{
  vl_api_hicn_api_punting_add_reply_t *rmp;
  int rv = HICN_ERROR_NONE;
  vlib_main_t *vm = vlib_get_main ();

  hicn_main_t *sm = &hicn_main;

  ip46_address_t prefix;
  prefix.as_u64[0] = clib_net_to_host_u64 (((u64 *) (&mp->prefix))[0]);
  prefix.as_u64[1] = clib_net_to_host_u64 (((u64 *) (&mp->prefix))[1]);
  u8 subnet_mask = mp->len;
  u32 swif = clib_net_to_host_u32 (mp->swif);

  rv =
    hicn_punt_interest_data_for_ethernet (vm, &prefix, subnet_mask, swif, 0);

  REPLY_MACRO (VL_API_HICN_API_PUNTING_ADD_REPLY /* , rmp, mp, rv */ );
}

static void vl_api_hicn_api_punting_del_t_handler
  (vl_api_hicn_api_punting_del_t * mp)
{
  vl_api_hicn_api_punting_del_reply_t *rmp;
  int rv = HICN_ERROR_NONE;

  hicn_main_t *sm = &hicn_main;

  rv = HICN_ERROR_NONE;

  REPLY_MACRO (VL_API_HICN_API_ROUTE_DEL_REPLY /* , rmp, mp, rv */ );
}

/************* APP FACE ****************/

static void vl_api_hicn_api_register_prod_app_t_handler
  (vl_api_hicn_api_register_prod_app_t * mp)
{
  vl_api_hicn_api_register_prod_app_reply_t *rmp;
  int rv = HICN_ERROR_NONE;

  hicn_main_t *sm = &hicn_main;

  hicn_prefix_t prefix;
  prefix.name.as_u64[0] = clib_net_to_host_u64 (((u64 *) (&mp->prefix))[0]);
  prefix.name.as_u64[1] = clib_net_to_host_u64 (((u64 *) (&mp->prefix))[1]);
  prefix.len = mp->len;
  u32 swif = clib_net_to_host_u32 (mp->swif);
  u32 cs_reserved = clib_net_to_host_u32 (mp->cs_reserved);
  u32 faceid;

  ip46_address_t prod_addr;
  ip46_address_reset (&prod_addr);
  rv = hicn_face_prod_add (&prefix, swif, &cs_reserved, &prod_addr, &faceid);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_HICN_API_REGISTER_PROD_APP_REPLY, (
    {
      rmp->prod_addr[0] = prod_addr.as_u64[0];
      rmp->prod_addr[1] = prod_addr.as_u64[1];
      rmp->cs_reserved = clib_net_to_host_u32(cs_reserved);
      rmp->faceid = clib_net_to_host_u32(faceid);
    }));
  /* *INDENT-ON* */
}

static void vl_api_hicn_api_register_cons_app_t_handler
  (vl_api_hicn_api_register_cons_app_t * mp)
{
  vl_api_hicn_api_register_cons_app_reply_t *rmp;
  int rv = HICN_ERROR_NONE;

  hicn_main_t *sm = &hicn_main;
  ip4_address_t src_addr4;
  ip6_address_t src_addr6;
  src_addr4.as_u32 = (u32) 0;
  src_addr6.as_u64[0] = (u64) 0;
  src_addr6.as_u64[1] = (u64) 1;

  u32 swif = clib_net_to_host_u32 (mp->swif);
  u32 faceid;

  rv = hicn_face_cons_add (&src_addr4, &src_addr6, swif, &faceid);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_HICN_API_REGISTER_CONS_APP_REPLY, (
    {
      rmp->src_addr4 = clib_net_to_host_u32(src_addr4.as_u32);
      rmp->src_addr6[0] = clib_net_to_host_u64(src_addr6.as_u64[0]);
      rmp->src_addr6[1] = clib_net_to_host_u64(src_addr6.as_u64[1]);
      rmp->faceid = clib_net_to_host_u32(faceid);
    }));
  /* *INDENT-ON* */
}

/************************************************************************************/

#define vl_msg_name_crc_list
#include <hicn/hicn_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (hicn_main_t * hm, api_main_t * am)
{
#define _(id,n,crc)                                                     \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + hm->msg_id_base);
  foreach_vl_msg_name_crc_hicn;
#undef _
}


/* Set up the API message handling tables */
clib_error_t *
hicn_api_plugin_hookup (vlib_main_t * vm)
{
  hicn_main_t *hm = &hicn_main;
  api_main_t *am = &api_main;

  /* Get a correctly-sized block of API message decode slots */
  u8 *name = format (0, "hicn_%08x%c", api_version, 0);
  hm->msg_id_base = vl_msg_api_get_msg_ids ((char *) name,
					    VL_MSG_FIRST_AVAILABLE);
  vec_free (name);

#define _(N, n)                                                  \
    vl_msg_api_set_handlers(hm->msg_id_base + VL_API_##N,       \
                            #n,                                 \
                            vl_api_##n##_t_handler,             \
                            vl_noop_handler,                    \
                            vl_api_##n##_t_endian,              \
                            vl_api_##n##_t_print,               \
                            sizeof(vl_api_##n##_t), 1);
  foreach_hicn_plugin_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (hm, am);

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

  ip_adjacency_t *ip_adj = adj_get (face->shared.adj);

  if (ip_adj != NULL)
    {
      reply->nh_addr[0] =
	clib_host_to_net_u64 (ip_adj->sub_type.nbr.next_hop.as_u64[0]);
      reply->nh_addr[1] =
	clib_host_to_net_u64 (ip_adj->sub_type.nbr.next_hop.as_u64[1]);
      reply->swif = clib_host_to_net_u32 (face->shared.sw_if);
      reply->flags = clib_host_to_net_u32 (face->shared.flags);
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
