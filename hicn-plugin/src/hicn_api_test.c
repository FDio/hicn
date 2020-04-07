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
#include <vnet/ip/ip_types_api.h>
#include <vnet/ip/ip_format_fns.h>

#define __plugin_msg_base hicn_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

#include <vpp/api/vpe.api_types.h>

#include <hicn/hicn_api.h>
#include "error.h"


/* Declare message IDs */
#include "hicn_msg_enum.h"

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

static ip46_type_t
ip_address_union_decode (const vl_api_address_union_t * in,
			 vl_api_address_family_t af, ip46_address_t * out)
{
  ip46_type_t type;

  switch (clib_net_to_host_u32 (af))
    {
    case ADDRESS_IP4:
      clib_memset (out, 0, sizeof (*out));
      clib_memcpy (&out->ip4, &in->ip4, sizeof (out->ip4));
      type = IP46_TYPE_IP4;
      break;
    case ADDRESS_IP6:
      clib_memcpy (&out->ip6, &in->ip6, sizeof (out->ip6));
      type = IP46_TYPE_IP6;
      break;
    default:
      ASSERT (!"Unkown address family in API address type");
      type = IP46_TYPE_ANY;
      break;
    }

  return type;
}

void
ip6_address_encode (const ip6_address_t * in, vl_api_ip6_address_t out)
{
  clib_memcpy (out, in, sizeof (*in));
}

void
ip6_address_decode (const vl_api_ip6_address_t in, ip6_address_t * out)
{
  clib_memcpy (out, in, sizeof (*out));
}

void
ip4_address_encode (const ip4_address_t * in, vl_api_ip4_address_t out)
{
  clib_memcpy (out, in, sizeof (*in));
}

void
ip4_address_decode (const vl_api_ip4_address_t in, ip4_address_t * out)
{
  clib_memcpy (out, in, sizeof (*out));
}

static void
ip_address_union_encode (const ip46_address_t * in,
			 vl_api_address_family_t af,
			 vl_api_address_union_t * out)
{
  if (ADDRESS_IP6 == clib_net_to_host_u32 (af))
    ip6_address_encode (&in->ip6, out->ip6);
  else
    ip4_address_encode (&in->ip4, out->ip4);
}

ip46_type_t
ip_address_decode (const vl_api_address_t * in, ip46_address_t * out)
{
  return (ip_address_union_decode (&in->un, in->af, out));
}

void
ip_address_encode (const ip46_address_t * in, ip46_type_t type,
		   vl_api_address_t * out)
{
  switch (type)
    {
    case IP46_TYPE_IP4:
      out->af = clib_net_to_host_u32 (ADDRESS_IP4);
      break;
    case IP46_TYPE_IP6:
      out->af = clib_net_to_host_u32 (ADDRESS_IP6);
      break;
    case IP46_TYPE_ANY:
      if (ip46_address_is_ip4 (in))
	out->af = clib_net_to_host_u32 (ADDRESS_IP4);
      else
	out->af = clib_net_to_host_u32 (ADDRESS_IP6);
      break;
    }
  ip_address_union_encode (in, out->af, &out->un);
}

fib_protocol_t
fib_proto_from_ip46 (ip46_type_t iproto)
{
  switch (iproto)
    {
    case IP46_TYPE_IP4:
      return FIB_PROTOCOL_IP4;
    case IP46_TYPE_IP6:
      return FIB_PROTOCOL_IP6;
    case IP46_TYPE_ANY:
      ASSERT (0);
      return FIB_PROTOCOL_IP4;
    }

  ASSERT (0);
  return FIB_PROTOCOL_IP4;
}

ip46_type_t
fib_proto_to_ip46 (fib_protocol_t fproto)
{
  switch (fproto)
    {
    case FIB_PROTOCOL_IP4:
      return (IP46_TYPE_IP4);
    case FIB_PROTOCOL_IP6:
      return (IP46_TYPE_IP6);
    case FIB_PROTOCOL_MPLS:
      return (IP46_TYPE_ANY);
    }
  ASSERT (0);
  return (IP46_TYPE_ANY);
}

void
ip_prefix_decode (const vl_api_prefix_t * in, fib_prefix_t * out)
{
  switch (clib_net_to_host_u32 (in->address.af))
    {
    case ADDRESS_IP4:
      out->fp_proto = FIB_PROTOCOL_IP4;
      break;
    case ADDRESS_IP6:
      out->fp_proto = FIB_PROTOCOL_IP6;
      break;
    }
  out->fp_len = in->len;
  out->___fp___pad = 0;
  ip_address_decode (&in->address, &out->fp_addr);
}

void
ip_prefix_encode (const fib_prefix_t * in, vl_api_prefix_t * out)
{
  out->len = in->fp_len;
  ip_address_encode (&in->fp_addr,
		     fib_proto_to_ip46 (in->fp_proto), &out->address);
}

/////////////////////////////////////////////////////

#define HICN_FACE_NULL ~0

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
  u32 ping_id;
} hicn_test_main_t;

hicn_test_main_t hicn_test_main;

#define foreach_standard_reply_retval_handler            \
_(hicn_api_node_params_set_reply)                        \
_(hicn_api_route_nhops_add_reply)                        \
_(hicn_api_route_del_reply)                              \
_(hicn_api_route_nhop_del_reply)                         \
_(hicn_api_enable_disable_reply)

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
_(HICN_API_FACE_GET_REPLY, hicn_api_face_get_reply)                     \
_(HICN_API_FACES_DETAILS, hicn_api_faces_details)                       \
_(HICN_API_FACE_STATS_DETAILS, hicn_api_face_stats_details)             \
_(HICN_API_ROUTE_NHOPS_ADD_REPLY, hicn_api_route_nhops_add_reply)       \
_(HICN_API_FACE_PARAMS_GET_REPLY, hicn_api_face_params_get_reply) \
_(HICN_API_ROUTE_GET_REPLY, hicn_api_route_get_reply)                   \
_(HICN_API_ROUTES_DETAILS, hicn_api_routes_details)                     \
_(HICN_API_ROUTE_DEL_REPLY, hicn_api_route_del_reply)                   \
_(HICN_API_ROUTE_NHOP_DEL_REPLY, hicn_api_route_nhop_del_reply)         \
_(HICN_API_STRATEGIES_GET_REPLY, hicn_api_strategies_get_reply)         \
_(HICN_API_STRATEGY_GET_REPLY, hicn_api_strategy_get_reply)             \
_(HICN_API_ENABLE_DISABLE_REPLY, hicn_api_enable_disable_reply)

static int
api_hicn_api_node_params_set (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  int enable_disable = 1;
  int pit_size = -1, cs_size = -1;
  f64 pit_max_lifetime_sec = -1.0f;
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
api_hicn_api_face_params_get (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_hicn_api_face_params_get_t *mp;
  u32 faceid = HICN_FACE_NULL, ret;

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
  if (faceid == HICN_FACE_NULL)
    {
      clib_warning ("Please specify face ID");
      return 1;
    }
  //Construct the API message
  M (HICN_API_FACE_PARAMS_GET, mp);
  mp->faceid = clib_host_to_net_u32 (faceid);

  //send it...
  S (mp);

  //Wait for a reply...
  W (ret);

  return ret;
}

static void
  vl_api_hicn_api_face_params_get_reply_t_handler
  (vl_api_hicn_api_face_params_get_reply_t * rmp)
{
  vat_main_t *vam = hicn_test_main.vat_main;
  i32 retval = ntohl (rmp->retval);
  u8 *sbuf = 0;
  ip46_address_t nat_addr;

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
  ip_address_decode (&rmp->nat_addr, &nat_addr);
  sbuf =
    format (0, "nat_addr %U", format_ip46_address,
	    &nat_addr, 0 /*IP46_ANY_TYPE */);

  fformat (vam->ofp, "%s swif %d flags %d\n",
	   sbuf,
	   clib_net_to_host_u32 (rmp->swif),
	   clib_net_to_host_i32 (rmp->flags));
}

static void
format_face (vl_api_hicn_face_t * rmp)
{
  vat_main_t *vam = hicn_test_main.vat_main;
  u8 *sbuf = 0;
  ip46_address_t nat_addr;
  ip46_address_t local_addr;

  vec_reset_length (sbuf);
  ip_address_decode (&rmp->nat_addr, &nat_addr);

  sbuf =
    format (0, "nat_addr %U", format_ip46_address,
	    &local_addr, 0 /*IP46_ANY_TYPE */);

  fformat (vam->ofp, "%s swif %d flags %d name %s\n",
	   sbuf,
	   clib_net_to_host_u32 (rmp->swif),
	   clib_net_to_host_i32 (rmp->flags), rmp->if_name);
}

static int
api_hicn_api_faces_dump (vat_main_t * vam)
{
  hicn_test_main_t *hm = &hicn_test_main;
  vl_api_hicn_api_faces_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for faces_dump");
      return -99;
    }

  M (HICN_API_FACES_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (hm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  fformat (vam->ofp, "Sending ping id=%d\n", hm->ping_id);

  vam->result_ready = 0;
  S (mp_ping);

  W (ret);
  return ret;
}

static void
  vl_api_hicn_api_faces_details_t_handler
  (vl_api_hicn_api_faces_details_t * mp)
{
  format_face (&(mp->face));
}

static int
api_hicn_api_face_get (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_hicn_api_face_get_t *mp;
  u32 faceid = HICN_FACE_NULL, ret;

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
  if (faceid == HICN_FACE_NULL)
    {
      clib_warning ("Please specify face ID");
      return 1;
    }
  //Construct the API message
  M (HICN_API_FACE_GET, mp);
  mp->faceid = clib_host_to_net_u32 (faceid);

  //send it...
  S (mp);

  //Wait for a reply...
  W (ret);

  return ret;
}


static void
  vl_api_hicn_api_face_get_reply_t_handler
  (vl_api_hicn_api_face_get_reply_t * rmp)
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
  format_face (&(rmp->face));
}



static int
api_hicn_api_face_stats_dump (vat_main_t * vam)
{
  hicn_test_main_t *hm = &hicn_test_main;
  vl_api_hicn_api_face_stats_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for memif_dump");
      return -99;
    }

  M (HICN_API_FACE_STATS_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (hm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  fformat (vam->ofp, "Sending ping id=%d\n", hm->ping_id);

  vam->result_ready = 0;
  S (mp_ping);

  W (ret);
  return ret;
}

/* face_stats-details message handler */
static void
  vl_api_hicn_api_face_stats_details_t_handler
  (vl_api_hicn_api_face_stats_details_t * mp)
{
  vat_main_t *vam = hicn_test_main.vat_main;

  fformat (vam->ofp, "face id %d\n"
	   "    interest rx           packets %16Ld\n"
	   "                          bytes %16Ld\n"
	   "    interest tx           packets %16Ld\n"
	   "                          bytes %16Ld\n"
	   "    data rx               packets %16Ld\n"
	   "                          bytes %16Ld\n"
	   "    data tx               packets %16Ld\n"
	   "                          bytes %16Ld\n",
	   clib_host_to_net_u32 (mp->faceid),
	   clib_host_to_net_u64 (mp->irx_packets),
	   clib_host_to_net_u64 (mp->irx_bytes),
	   clib_host_to_net_u64 (mp->itx_packets),
	   clib_host_to_net_u64 (mp->itx_bytes),
	   clib_host_to_net_u64 (mp->drx_packets),
	   clib_host_to_net_u64 (mp->drx_bytes),
	   clib_host_to_net_u64 (mp->dtx_packets),
	   clib_host_to_net_u64 (mp->dtx_bytes));
}

static int
api_hicn_api_route_get (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;

  vl_api_hicn_api_route_get_t *mp;
  fib_prefix_t prefix;
  int ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "prefix %U/%d", unformat_ip46_address,
		    &prefix.fp_addr, IP46_TYPE_ANY, &prefix.fp_len))
	{;
	}
      else
	{
	  break;
	}
    }

  /* Check parse */
  if (((prefix.fp_addr.as_u64[0] == 0) && (prefix.fp_addr.as_u64[1] == 0))
      || (prefix.fp_len == 0))
    {
      clib_warning ("Please specify a valid prefix...");
      return 1;
    }
  //Construct the API message
  M (HICN_API_ROUTE_GET, mp);
  if (!ip46_address_is_ip4 (&(prefix.fp_addr)))
    prefix.fp_proto = fib_proto_from_ip46 (IP46_TYPE_IP6);
  ip_prefix_encode (&prefix, &mp->prefix);

  //send it...
  S (mp);

  //Wait for a reply...
  W (ret);

  return ret;
}

static int
api_hicn_api_routes_dump (vat_main_t * vam)
{

  hicn_test_main_t *hm = &hicn_test_main;
  vl_api_hicn_api_route_get_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for routes_dump");
      return -99;
    }

  M (HICN_API_ROUTES_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (hm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  fformat (vam->ofp, "Sending ping id=%d\n", hm->ping_id);

  vam->result_ready = 0;
  S (mp_ping);

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

  fformat (vam->ofp, "%s\n Strategy: %d\n",
	   sbuf, clib_net_to_host_u32 (rmp->strategy_id));
}

/* face_stats-details message handler */
static void
  vl_api_hicn_api_routes_details_t_handler
  (vl_api_hicn_api_routes_details_t * mp)
{
  vat_main_t *vam = hicn_test_main.vat_main;
  fib_prefix_t prefix;
  u32 faceid;
  u8 *sbuf = 0;
  vec_reset_length (sbuf);

  ip_prefix_decode (&mp->prefix, &prefix);
  sbuf =
    format (sbuf, "Prefix: %U/%u\n", format_ip46_address, &prefix.fp_addr, 0,
	    prefix.fp_len);

  sbuf = format (sbuf, "Faces: \n");
  for (int i = 0; i < mp->nfaces; i++)
    {
      faceid = clib_net_to_host_u32 (mp->faceids[i]);
      sbuf = format (sbuf, " faceid %d\n", faceid);
    }

  fformat (vam->ofp, "%sStrategy: %d\n",
	   sbuf, clib_net_to_host_u32 (mp->strategy_id));
}

static int
api_hicn_api_route_nhops_add (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_hicn_api_route_nhops_add_t *mp;

  fib_prefix_t prefix;
  u32 faceid = 0;
  int ret;


  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add prefix %U/%d", unformat_ip46_address,
		    &prefix.fp_addr, IP46_TYPE_ANY, &prefix.fp_len))
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
  if (((prefix.fp_addr.as_u64[0] == 0) && (prefix.fp_addr.as_u64[1] == 0))
      || (prefix.fp_len == 0) || (faceid == 0))
    {
      clib_warning ("Please specify prefix and faceid...");
      return 1;
    }
  /* Construct the API message */
  M (HICN_API_ROUTE_NHOPS_ADD, mp);
  ip_prefix_encode (&prefix, &mp->prefix);

  if (!ip46_address_is_ip4 (&(prefix.fp_addr)))
    prefix.fp_proto = fib_proto_from_ip46 (IP46_TYPE_IP6);

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

  fib_prefix_t prefix;
  int ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "prefix %U/%d", unformat_ip46_address,
		    &prefix.fp_addr, IP46_TYPE_ANY, &prefix.fp_len))
	{;
	}
      else
	{
	  break;
	}
    }

  /* Check parse */
  if (((prefix.fp_addr.as_u64[0] == 0) && (prefix.fp_addr.as_u64[1] == 0))
      || (prefix.fp_len == 0))
    {
      clib_warning ("Please specify prefix...");
      return 1;
    }
  /* Construct the API message */
  M (HICN_API_ROUTE_DEL, mp);
  ip_prefix_encode (&prefix, &mp->prefix);

  if (!ip46_address_is_ip4 (&(prefix.fp_addr)))
    prefix.fp_proto = fib_proto_from_ip46 (IP46_TYPE_IP6);

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

  fib_prefix_t prefix;
  int faceid = 0, ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del prefix %U/%d", unformat_ip46_address,
		    &prefix.fp_addr, IP46_TYPE_ANY, &prefix.fp_len))
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
  if (((prefix.fp_addr.as_u64[0] == 0) && (prefix.fp_addr.as_u64[1] == 0))
      || (prefix.fp_len == 0) || (faceid == HICN_FACE_NULL))
    {
      clib_warning ("Please specify prefix and faceid...");
      return 1;
    }
  /* Construct the API message */
  M (HICN_API_ROUTE_NHOP_DEL, mp);
  ip_prefix_encode (&prefix, &mp->prefix);

  if (!ip46_address_is_ip4 (&(prefix.fp_addr)))
    prefix.fp_proto = fib_proto_from_ip46 (IP46_TYPE_IP6);

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
api_hicn_api_enable_disable (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_hicn_api_enable_disable_t *mp;
  int ret;

  fib_prefix_t prefix;
  vl_api_hicn_action_type_t en_dis = HICN_ENABLE;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "prefix %U/%d", unformat_ip46_address,
		    &prefix.fp_addr, IP46_TYPE_ANY, &prefix.fp_len))
	{;
	}
      else if (unformat (input, "disable"))
          {;
            en_dis = HICN_DISABLE;
          }
      else
	{
	  break;
	}
    }

  /* Check parse */
  if (((prefix.fp_addr.as_u64[0] == 0) && (prefix.fp_addr.as_u64[1] == 0))
      || (prefix.fp_len == 0))
    {
      clib_warning ("Please specify a valid prefix...");
      return 1;
    }

  prefix.fp_proto = ip46_address_is_ip4 (&(prefix.fp_addr)) ? FIB_PROTOCOL_IP4 :
                                         FIB_PROTOCOL_IP6;

  //Construct the API message
  M (HICN_API_ENABLE_DISABLE, mp);

  ip_prefix_encode (&prefix, &mp->prefix);
  mp->enable_disable = en_dis;

  //send it...
  S (mp);

  //Wait for a reply...
  W (ret);

  return ret;
}


#include <hicn/hicn.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
