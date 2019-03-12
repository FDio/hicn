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

#include <inttypes.h>

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/format.h>

#define __plugin_msg_base hicn_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>


#include <hicn/hicn_api.h>
#include "error.h"

// uword unformat_sw_if_index(unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include "hicn_msg_enum.h"

/* declare message handlers for each api */

#define vl_endianfun		/* define message structures */
#include "hicn_all_api_h.h"
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include "hicn_all_api_h.h"
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n, v) static u32 api_version=(v);
#include "hicn_all_api_h.h"
#undef vl_api_version

/* SUPPORTING FUNCTIONS NOT LOADED BY VPP_API_TEST */
uword
unformat_ip46_address (unformat_input_t * input, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  ip46_type_t type = va_arg (*args, ip46_type_t);
  if ((type != IP46_TYPE_IP6) &&
      unformat (input, "%U", unformat_ip4_address, &ip46->ip4))
    {
      ip46_address_mask_ip4 (ip46);
      return 1;
    }
  else if ((type != IP46_TYPE_IP4) &&
	   unformat (input, "%U", unformat_ip6_address, &ip46->ip6))
    {
      return 1;
    }
  return 0;
}

/////////////////////////////////////////////////////

#define HICN_FACE_NULL ~0

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} hicn_test_main_t;

hicn_test_main_t hicn_test_main;

#define foreach_standard_reply_retval_handler            \
_(hicn_api_node_params_set_reply)                        \
_(hicn_api_face_ip_del_reply)                            \
_(hicn_api_route_nhops_add_reply)                        \
_(hicn_api_route_del_reply)                              \
_(hicn_api_route_nhop_del_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = hicn_test_main.vat_main;     \
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {					\
	    fformat (vam->ofp,"%s\n", get_error_string(retval));\
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
    }
foreach_standard_reply_retval_handler;
#undef _

/*
 * Table of message reply handlers, must include boilerplate handlers we just
 * generated
 */
#define foreach_vpe_api_reply_msg                                       \
_(HICN_API_NODE_PARAMS_SET_REPLY, hicn_api_node_params_set_reply)       \
_(HICN_API_NODE_PARAMS_GET_REPLY, hicn_api_node_params_get_reply)       \
_(HICN_API_NODE_STATS_GET_REPLY, hicn_api_node_stats_get_reply)         \
_(HICN_API_FACE_IP_DEL_REPLY, hicn_api_face_ip_del_reply)               \
_(HICN_API_FACE_IP_ADD_REPLY, hicn_api_face_ip_add_reply)               \
_(HICN_API_ROUTE_NHOPS_ADD_REPLY, hicn_api_route_nhops_add_reply)       \
_(HICN_API_FACE_IP_PARAMS_GET_REPLY, hicn_api_face_ip_params_get_reply) \
_(HICN_API_ROUTE_GET_REPLY, hicn_api_route_get_reply)                   \
_(HICN_API_ROUTE_DEL_REPLY, hicn_api_route_del_reply)                   \
_(HICN_API_ROUTE_NHOP_DEL_REPLY, hicn_api_route_nhop_del_reply)		    \
_(HICN_API_STRATEGIES_GET_REPLY, hicn_api_strategies_get_reply)		    \
_(HICN_API_STRATEGY_GET_REPLY, hicn_api_strategy_get_reply)             \
_(HICN_API_REGISTER_PROD_APP_REPLY, hicn_api_register_prod_app_reply)   \
_(HICN_API_REGISTER_CONS_APP_REPLY, hicn_api_register_cons_app_reply)


static int
api_hicn_api_node_params_set (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  int enable_disable = 1;
  int pit_size = -1, cs_size = -1;
  f64 pit_dflt_lifetime_sec = -1.0f;
  f64 pit_min_lifetime_sec = -1.0f, pit_max_lifetime_sec = -1.0f;
  int ret;

  vl_api_hicn_api_node_params_set_t *mp;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	{
	  enable_disable = 0;
	}
      else if (unformat (input, "PIT size %d", &pit_size))
	{;
	}
      else if (unformat (input, "CS size %d", &cs_size))
	{;
	}
      else if (unformat (input, "PIT dfltlife %f", &pit_dflt_lifetime_sec))
	{;
	}
      else if (unformat (input, "PIT minlife %f", &pit_min_lifetime_sec))
	{;
	}
      else if (unformat (input, "PIT maxlife %f", &pit_max_lifetime_sec))
	{;
	}
      else
	{
	  break;
	}
    }

  /* Construct the API message */
  M (HICN_API_NODE_PARAMS_SET, mp);
  mp->enable_disable = enable_disable;
  mp->pit_max_size = clib_host_to_net_i32 (pit_size);
  mp->cs_max_size = clib_host_to_net_i32 (cs_size);
  mp->pit_dflt_lifetime_sec = pit_dflt_lifetime_sec;
  mp->pit_min_lifetime_sec = pit_min_lifetime_sec;
  mp->pit_max_lifetime_sec = pit_max_lifetime_sec;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return ret;
}

static int
api_hicn_api_node_params_get (vat_main_t * vam)
{
  vl_api_hicn_api_node_params_get_t *mp;
  int ret;

  //Construct the API message
  M (HICN_API_NODE_PARAMS_GET, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return ret;
}

static void
  vl_api_hicn_api_node_params_get_reply_t_handler
  (vl_api_hicn_api_node_params_get_reply_t * mp)
{
  vat_main_t *vam = hicn_test_main.vat_main;
  i32 retval = ntohl (mp->retval);

  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
      return;
    }
  vam->retval = retval;
  vam->result_ready = 1;

  if (vam->retval < 0)
    {
      //vpp_api_test infra will also print out string form of error
      fformat (vam->ofp, "   (API call error: %d)\n", vam->retval);
      return;
    }
  fformat (vam->ofp,
	   "Enabled %d\n"
	   "  Features: cs:%d\n"
	   "  PIT size %d\n"
	   "  PIT lifetime dflt %.3f, min %.3f, max %.3f\n"
	   "  CS size %d\n",
	   mp->is_enabled,
	   mp->feature_cs,
	   clib_net_to_host_u32 (mp->pit_max_size),
	   mp->pit_dflt_lifetime_sec,
	   mp->pit_min_lifetime_sec,
	   mp->pit_max_lifetime_sec, clib_net_to_host_u32 (mp->cs_max_size));
}

static int
api_hicn_api_node_stats_get (vat_main_t * vam)
{
  vl_api_hicn_api_node_stats_get_t *mp;
  int ret;

  /* Construct the API message */
  M (HICN_API_NODE_STATS_GET, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return ret;
}

static void
  vl_api_hicn_api_node_stats_get_reply_t_handler
  (vl_api_hicn_api_node_stats_get_reply_t * rmp)
{
  vat_main_t *vam = hicn_test_main.vat_main;
  i32 retval = ntohl (rmp->retval);

  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
      return;
    }
  vam->retval = retval;
  vam->result_ready = 1;

  if (vam->retval < 0)
    {
      //vpp_api_test infra will also print out string form of error
      fformat (vam->ofp, "   (API call error: %d)\n", vam->retval);
      return;
    }
  else
    {
      fformat (vam->ofp,	//compare hicn_cli_show_command_fn block:should match
	       "  PIT entries (now): %d\n"
	       "  CS entries (now): %d\n"
	       "  Forwarding statistics:"
	       "    pkts_processed: %d\n"
	       "    pkts_interest_count: %d\n"
	       "    pkts_data_count: %d\n"
	       "    pkts_nak_count: %d\n"
	       "    pkts_from_cache_count: %d\n"
	       "    pkts_nacked_interests_count: %d\n"
	       "    pkts_nak_hoplimit_count: %d\n"
	       "    pkts_nak_no_route_count: %d\n"
	       "    pkts_no_pit_count: %d\n"
	       "    pit_expired_count: %d\n"
	       "    cs_expired_count: %d\n"
	       "    cs_lru_count: %d\n"
	       "    pkts_drop_no_buf: %d\n"
	       "    interests_aggregated: %d\n"
	       "    interests_retransmitted: %d\n",
	       clib_net_to_host_u64 (rmp->pit_entries_count),
	       clib_net_to_host_u64 (rmp->cs_entries_count),
	       clib_net_to_host_u64 (rmp->pkts_processed),
	       clib_net_to_host_u64 (rmp->pkts_interest_count),
	       clib_net_to_host_u64 (rmp->pkts_data_count),
	       clib_net_to_host_u64 (rmp->pkts_from_cache_count),
	       clib_net_to_host_u64 (rmp->pkts_no_pit_count),
	       clib_net_to_host_u64 (rmp->pit_expired_count),
	       clib_net_to_host_u64 (rmp->cs_expired_count),
	       clib_net_to_host_u64 (rmp->cs_lru_count),
	       clib_net_to_host_u64 (rmp->pkts_drop_no_buf),
	       clib_net_to_host_u64 (rmp->interests_aggregated),
	       clib_net_to_host_u64 (rmp->interests_retx));
    }
}

static int
api_hicn_api_face_ip_add (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  ip46_address_t local_addr = { 0 };
  ip46_address_t remote_addr = { 0 };
  int ret = HICN_ERROR_NONE;
  int sw_if = 0;
  vl_api_hicn_api_face_ip_add_t *mp;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "local %U", unformat_ip4_address, &local_addr.ip4));
      else
	if (unformat
	    (input, "local %U", unformat_ip6_address, &local_addr.ip6));
      else
	if (unformat
	    (input, "remote %U", unformat_ip4_address, &remote_addr.ip4));
      else
	if (unformat
	    (input, "remote %U", unformat_ip6_address, &remote_addr.ip6));
      else if (unformat (input, "intfc %d", &sw_if));
      else
	{
	  break;
	}
    }

  /* Check for presence of both addresses */
  if ((!ip46_address_is_zero (&local_addr)
       && ! !ip46_address_is_zero (&remote_addr)))
    {
      clib_warning
	("Incomplete IP face. Please specify local and remote address");
      return (1);
    }
  /* Construct the API message */
  M (HICN_API_FACE_IP_ADD, mp);
  mp->local_addr[0] = clib_host_to_net_u64 (local_addr.as_u64[0]);
  mp->local_addr[1] = clib_host_to_net_u64 (local_addr.as_u64[1]);
  mp->remote_addr[0] = clib_host_to_net_u64 (remote_addr.as_u64[0]);
  mp->remote_addr[1] = clib_host_to_net_u64 (remote_addr.as_u64[1]);
  mp->swif = clib_host_to_net_u32 (sw_if);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return ret;
}

static void
  vl_api_hicn_api_face_ip_add_reply_t_handler
  (vl_api_hicn_api_face_ip_add_reply_t * rmp)
{
  vat_main_t *vam = hicn_test_main.vat_main;
  i32 retval = ntohl (rmp->retval);

  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
      return;
    }
  vam->retval = retval;
  vam->result_ready = 1;

  if (vam->retval < 0)
    {
      //vpp_api_test infra will also print out string form of error
      fformat (vam->ofp, "   (API call error: %d)\n", vam->retval);
      return;
    }
  fformat (vam->ofp, "New Face ID: %d\n", ntohl (rmp->faceid));
}

static int
api_hicn_api_face_ip_del (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_hicn_api_face_ip_del_t *mp;
  int faceid = 0, ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "face %d", &faceid))
	{;
	}
      else
	{
	  break;
	}
    }

  //Check for presence of face ID
  if (faceid == 0)
    {
      clib_warning ("Please specify face ID");
      return 1;
    }
  //Construct the API message
  M (HICN_API_FACE_IP_DEL, mp);
  mp->faceid = clib_host_to_net_i32 (faceid);

  //send it...
  S (mp);

  //Wait for a reply...
  W (ret);

  return ret;
}

static int
api_hicn_api_face_ip_params_get (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_hicn_api_face_ip_params_get_t *mp;
  int faceid = 0, ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "face %d", &faceid))
	{;
	}
      else
	{
	  break;
	}
    }

  //Check for presence of face ID
  if (faceid == 0)
    {
      clib_warning ("Please specify face ID");
      return 1;
    }
  //Construct the API message
  M (HICN_API_FACE_IP_PARAMS_GET, mp);
  mp->faceid = clib_host_to_net_i32 (faceid);

  //send it...
  S (mp);

  //Wait for a reply...
  W (ret);

  return ret;
}

static void
  vl_api_hicn_api_face_ip_params_get_reply_t_handler
  (vl_api_hicn_api_face_ip_params_get_reply_t * rmp)
{
  vat_main_t *vam = hicn_test_main.vat_main;
  i32 retval = ntohl (rmp->retval);
  u8 *sbuf = 0;
  ip46_address_t remote_addr;
  ip46_address_t local_addr;

  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
      return;
    }
  vam->retval = retval;
  vam->result_ready = 1;

  if (vam->retval < 0)
    {
      //vpp_api_test infra will also print out string form of error
      fformat (vam->ofp, "   (API call error: %d)\n", vam->retval);
      return;
    }
  vec_reset_length (sbuf);
  local_addr.as_u64[0] = clib_net_to_host_u64 (rmp->local_addr[0]);
  local_addr.as_u64[1] = clib_net_to_host_u64 (rmp->local_addr[1]);
  remote_addr.as_u64[0] = clib_net_to_host_u64 (rmp->remote_addr[0]);
  remote_addr.as_u64[1] = clib_net_to_host_u64 (rmp->remote_addr[1]);
  sbuf =
    format (0, "local_addr %U remote_addr %U", format_ip46_address,
	    &local_addr, 0 /*IP46_ANY_TYPE */ , format_ip46_address,
	    &remote_addr, 0 /*IP46_ANY_TYPE */ );

  fformat (vam->ofp, "%s swif %d flags %d\n",
	   sbuf,
	   clib_net_to_host_u16 (rmp->swif),
	   clib_net_to_host_i32 (rmp->flags));
}

static int
api_hicn_api_route_get (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;

  vl_api_hicn_api_route_get_t *mp;
  ip46_address_t prefix;
  u8 plen;
  int ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "prefix %U/%d", unformat_ip46_address,
		    &prefix, IP46_TYPE_ANY, &plen))
	{;
	}
      else
	{
	  break;
	}
    }

  /* Check parse */
  if (((prefix.as_u64[0] == 0) && (prefix.as_u64[1] == 0)) || (plen == 0))
    {
      clib_warning ("Please specify a valid prefix...");
      return 1;
    }
  //Construct the API message
  M (HICN_API_ROUTE_GET, mp);
  mp->prefix[0] = clib_host_to_net_u64 (((u64 *) & prefix)[0]);
  mp->prefix[1] = clib_host_to_net_u64 (((u64 *) & prefix)[1]);
  mp->len = plen;

  //send it...
  S (mp);

  //Wait for a reply...
  W (ret);

  return ret;
}

static void
vl_api_hicn_api_route_get_reply_t_handler (vl_api_hicn_api_route_get_reply_t *
					   rmp)
{
  vat_main_t *vam = hicn_test_main.vat_main;
  i32 retval = ntohl (rmp->retval);
  u8 *sbuf = 0;

  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
      return;
    }
  vam->retval = retval;
  vam->result_ready = 1;

  if (vam->retval < 0)
    {
      //vpp_api_test infra will also print out string form of error
      fformat (vam->ofp, "   (API call error: %d)\n", vam->retval);
      return;
    }
  int i = 0;
  u8 null_face = 0;
  u32 faceid;

  vec_reset_length (sbuf);
  sbuf = format (sbuf, "Faces: \n");
  while (i < 1000 && !null_face)
    {
      faceid = clib_net_to_host_u32 (rmp->faceids[i]);
      if (faceid != HICN_FACE_NULL)
	{
	  sbuf =
	    format (sbuf, "faceid %d",
		    clib_net_to_host_u32 (rmp->faceids[i]));
	  i++;
	}
      else
	{
	  null_face = 1;
	}
    }

  fformat (vam->ofp, "%s\n Strategy: %d",
	   sbuf, clib_net_to_host_u32 (rmp->strategy_id));
}

static int
api_hicn_api_route_nhops_add (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_hicn_api_route_nhops_add_t *mp;

  ip46_address_t prefix;
  u8 plen;
  u32 faceid = 0;
  int ret;


  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add prefix %U/%d", unformat_ip46_address,
		    &prefix, IP46_TYPE_ANY, &plen))
	{;
	}
      else if (unformat (input, "face %d", &faceid))
	{;
	}
      else
	{
	  break;
	}
    }

  /* Check parse */
  if (((prefix.as_u64[0] == 0) && (prefix.as_u64[1] == 0)) || (plen == 0)
      || (faceid == 0))
    {
      clib_warning ("Please specify prefix and faceid...");
      return 1;
    }
  /* Construct the API message */
  M (HICN_API_ROUTE_NHOPS_ADD, mp);
  mp->prefix[0] = clib_host_to_net_u64 (((u64 *) & prefix)[0]);
  mp->prefix[1] = clib_host_to_net_u64 (((u64 *) & prefix)[1]);
  mp->len = plen;

  mp->face_ids[0] = clib_host_to_net_u32 (faceid);
  mp->n_faces = 1;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return ret;
}

static int
api_hicn_api_route_del (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_hicn_api_route_del_t *mp;

  ip46_address_t prefix;
  u8 plen;
  int ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "prefix %U/%d", unformat_ip46_address,
		    &prefix, IP46_TYPE_ANY, &plen))
	{;
	}
      else
	{
	  break;
	}
    }

  /* Check parse */
  if (((prefix.as_u64[0] == 0) && (prefix.as_u64[1] == 0)) || (plen == 0))
    {
      clib_warning ("Please specify prefix...");
      return 1;
    }
  /* Construct the API message */
  M (HICN_API_ROUTE_DEL, mp);
  mp->prefix[0] = clib_host_to_net_u64 (((u64 *) & prefix)[0]);
  mp->prefix[1] = clib_host_to_net_u64 (((u64 *) & prefix)[1]);
  mp->len = plen;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return ret;

}

static int
api_hicn_api_route_nhop_del (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_hicn_api_route_nhop_del_t *mp;

  ip46_address_t prefix;
  u8 plen;
  int faceid = 0, ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del prefix %U/%d", unformat_ip46_address,
		    &prefix, IP46_TYPE_ANY, &plen))
	{;
	}
      else if (unformat (input, "face %d", &faceid))
	{;
	}
      else
	{
	  break;
	}
    }

  /* Check parse */
  if (((prefix.as_u64[0] == 0) && (prefix.as_u64[1] == 0)) || (plen == 0)
      || (faceid == HICN_FACE_NULL))
    {
      clib_warning ("Please specify prefix and faceid...");
      return 1;
    }
  /* Construct the API message */
  M (HICN_API_ROUTE_NHOP_DEL, mp);
  mp->prefix[0] = clib_host_to_net_u64 (((u64 *) & prefix)[0]);
  mp->prefix[1] = clib_host_to_net_u64 (((u64 *) & prefix)[1]);
  mp->len = plen;

  mp->faceid = clib_host_to_net_u32 (faceid);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return ret;
}

static int
api_hicn_api_strategies_get (vat_main_t * vam)
{
  vl_api_hicn_api_strategies_get_t *mp;
  int ret;

  //TODO
  /* Construct the API message */
  M (HICN_API_STRATEGIES_GET, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return ret;
}

static void
  vl_api_hicn_api_strategies_get_reply_t_handler
  (vl_api_hicn_api_strategies_get_reply_t * mp)
{
  vat_main_t *vam = hicn_test_main.vat_main;
  i32 retval = ntohl (mp->retval);
  u8 *sbuf = 0;

  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
      return;
    }
  vam->retval = retval;
  vam->result_ready = 1;

  if (vam->retval < 0)
    {
      //vpp_api_test infra will also print out string form of error
      fformat (vam->ofp, "   (API call error: %d)\n", vam->retval);
      return;
    }
  int n_strategies = clib_net_to_host_i32 (mp->n_strategies);

  vec_reset_length (sbuf);
  sbuf = format (sbuf, "Available strategies:\n");

  int i;
  for (i = 0; i < n_strategies; i++)
    {
      u32 strategy_id = clib_net_to_host_u32 (mp->strategy_id[i]);
      sbuf = format (sbuf, "%d ", strategy_id);
    }
  fformat (vam->ofp, "%s", sbuf);
}

static int
api_hicn_api_strategy_get (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_hicn_api_strategy_get_t *mp;
  int ret;

  u32 strategy_id = HICN_STRATEGY_NULL;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "strategy %d", strategy_id))
	{;
	}
      else
	{
	  break;
	}
    }

  if (strategy_id == HICN_STRATEGY_NULL)
    {
      clib_warning ("Please specify strategy id...");
      return 1;
    }

  /* Construct the API message */
  M (HICN_API_STRATEGY_GET, mp);
  mp->strategy_id = clib_host_to_net_u32 (strategy_id);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return ret;
}

static void
  vl_api_hicn_api_strategy_get_reply_t_handler
  (vl_api_hicn_api_strategy_get_reply_t * mp)
{
  vat_main_t *vam = hicn_test_main.vat_main;
  i32 retval = ntohl (mp->retval);

  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
      return;
    }
  vam->retval = retval;
  vam->result_ready = 1;

  if (vam->retval < 0)
    {
      //vpp_api_test infra will also print out string form of error
      fformat (vam->ofp, "   (API call error: %d)\n", vam->retval);
      return;
    }
  fformat (vam->ofp, "%s", mp->description);
}

static int
api_hicn_api_register_prod_app (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_hicn_api_register_prod_app_t *mp;
  ip46_address_t prefix;
  int plen;
  u32 swif = ~0;
  int ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "prefix %U/%d", unformat_ip46_address,
		    &prefix, IP46_TYPE_ANY, &plen))
	{;
	}
      else if (unformat (input, "id %d", &swif))
	{;
	}
      else
	{
	  break;
	}
    }

  /* Check parse */
  if (((prefix.as_u64[0] == 0) && (prefix.as_u64[1] == 0)) || (plen == 0))
    {
      clib_warning ("Please specify prefix...");
      return 1;
    }
  /* Construct the API message */
  M (HICN_API_REGISTER_PROD_APP, mp);
  mp->prefix[0] = clib_host_to_net_u64 (prefix.as_u64[0]);
  mp->prefix[1] = clib_host_to_net_u64 (prefix.as_u64[1]);
  mp->len = (u8) plen;

  mp->swif = clib_host_to_net_u32 (swif);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return ret;
}

static void
  vl_api_hicn_api_register_prod_app_reply_t_handler
  (vl_api_hicn_api_register_prod_app_reply_t * mp)
{
  vat_main_t *vam = hicn_test_main.vat_main;
  i32 retval = ntohl (mp->retval);

  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
      return;
    }
  vam->retval = retval;
  vam->result_ready = 1;

  if (vam->retval < 0)
    {
      //vpp_api_test infra will also print out string form of error
      fformat (vam->ofp, "   (API call error: %d)\n", vam->retval);
      return;
    }
}

static int
api_hicn_api_register_cons_app (vat_main_t * vam)
{
  vl_api_hicn_api_register_cons_app_t *mp;
  int ret;

  /* Construct the API message */
  M (HICN_API_REGISTER_CONS_APP, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return ret;
}

static void
  vl_api_hicn_api_register_cons_app_reply_t_handler
  (vl_api_hicn_api_register_cons_app_reply_t * mp)
{
  vat_main_t *vam = hicn_test_main.vat_main;
  i32 retval = ntohl (mp->retval);

  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
      return;
    }
  vam->retval = retval;
  vam->result_ready = 1;

  if (vam->retval < 0)
    {
      //vpp_api_test infra will also print out string form of error
      fformat (vam->ofp, "   (API call error: %d)\n", vam->retval);
      return;
    }
  ip4_address_t src_addr4;
  src_addr4.as_u32 = clib_net_to_host_u32 (mp->src_addr4);
  ip6_address_t src_addr6;
  src_addr6.as_u64[0] = clib_net_to_host_u64 (mp->src_addr6[0]);
  src_addr6.as_u64[1] = clib_net_to_host_u64 (mp->src_addr6[1]);

  fformat (vam->ofp,
	   "ip4 address %U\n"
	   "ip6 address :%U\n"
	   "appif id :%d\n",
	   format_ip4_address, &src_addr4, format_ip6_address, &src_addr6);
}

/*
 * List of messages that the api test plugin sends, and that the data plane
 * plugin processes
 */
#define foreach_vpe_api_msg                                             \
_(hicn_api_node_params_set, "PIT size <sz> CS size <sz>"                \
  "PIT minlimit <f> PIT maxlimit <f> [disable] ")                       \
_(hicn_api_node_params_get, "")                                         \
_(hicn_api_node_stats_get, "")                                          \
_(hicn_api_face_ip_del, "face <faceID>")                                \
_(hicn_api_face_ip_add, "add <swif> <address>")                         \
_(hicn_api_route_nhops_add, "add prefix <IP4/IP6>/<subnet> face <faceID> weight <weight>") \
_(hicn_api_face_ip_params_get, "face <faceID>")                         \
_(hicn_api_route_get, "prefix <IP4/IP6>/<subnet>")                      \
_(hicn_api_route_del, "prefix <IP4/IP6>/<subnet>")                      \
_(hicn_api_route_nhop_del, "del prefix <IP4/IP6>/<subnet> face <faceID>") \
_(hicn_api_strategies_get, "")                                          \
_(hicn_api_strategy_get, "strategy <id>")                               \
_(hicn_api_register_prod_app, "prefix <IP4/IP6>/<subnet> id <appif_id>") \
_(hicn_api_register_cons_app, "")

void
hicn_vat_api_hookup (vat_main_t * vam)
{
  hicn_test_main_t *sm = &hicn_test_main;
  /* Hook up handlers for replies from the data plane plug-in */
#define _(N, n)                                                  \
  vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),        \
                          #n,                                    \
                          vl_api_##n##_t_handler,                \
                          vl_noop_handler,                       \
                          vl_api_##n##_t_endian,                 \
                          vl_api_##n##_t_print,                  \
                          sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_reply_msg;
#undef _

  /* API messages we can send */
#define _(n, h) hash_set_mem (vam->function_by_name, #n, api_##n);
  foreach_vpe_api_msg;
#undef _

  /* Help strings */
#define _(n, h) hash_set_mem (vam->help_by_name, #n, h);
  foreach_vpe_api_msg;
#undef _
}

clib_error_t *
vat_plugin_register (vat_main_t * vam)
{
  hicn_test_main_t *sm = &hicn_test_main;
  u8 *name;

  sm->vat_main = vam;

  /* Ask the vpp engine for the first assigned message-id */
  name = format (0, "hicn_%08x%c", api_version, 0);
  sm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (sm->msg_id_base != (u16) ~ 0)
    hicn_vat_api_hookup (vam);

  vec_free (name);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
