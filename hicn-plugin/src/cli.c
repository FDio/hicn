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
#include <vppinfra/error.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vnet/udp/udp.h>	// port registration
#include <vnet/ip/ip6_packet.h>	// ip46_address_t
#include <vnet/ip/format.h>
#include <vnet/fib/fib_types.h>

#include "hicn.h"
#include "infra.h"
#include "parser.h"
#include "mgmt.h"
#include "strategy_dpo_manager.h"
#include "strategy.h"
#include "pg.h"
#include "error.h"
#include "faces/face.h"
#include "route.h"
#include "punt.h"
#include "hicn_api.h"

extern ip_version_t ipv4;
extern ip_version_t ipv6;

static vl_api_hicn_api_node_params_set_t node_ctl_params = {
  .pit_max_size = -1,
  .pit_max_lifetime_sec = -1.0f,
  .cs_max_size = -1,
  .cs_reserved_app = -1,
};

typedef enum
{
  IP,
  ETHERNET,
} interface_type_t;

/*
 * Supporting function that return if the interface is IP or ethernet
 */
static interface_type_t
hicn_cli_is_ip_interface (vlib_main_t * vm,
			  vnet_main_t * vnm, u32 sw_if_index)
{

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, sw_if_index);

  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);
  if (!strcmp (dev_class->name, "Loopback"))
    {
      return IP;
    }
  return ETHERNET;

}

/*
 * cli handler for 'control start'
 */
static clib_error_t *
hicn_cli_node_ctl_start_set_command_fn (vlib_main_t * vm,
					unformat_input_t * main_input,
					vlib_cli_command_t * cmd)
{
  int ret;

  ret = hicn_infra_plugin_enable_disable (1 /* enable */ ,
					  node_ctl_params.pit_max_size,
					  node_ctl_params.
					  pit_max_lifetime_sec,
					  node_ctl_params.cs_max_size,
					  node_ctl_params.cs_reserved_app);

  vlib_cli_output (vm, "hicn: fwdr initialize => %s\n",
		   get_error_string (ret));

  return (ret == HICN_ERROR_NONE) ? 0 : clib_error_return (0,
							   get_error_string
							   (ret));
}

/*
 * cli handler for 'control stop'
 */
static clib_error_t *
hicn_cli_node_ctl_stop_set_command_fn (vlib_main_t * vm,
				       unformat_input_t * main_input,
				       vlib_cli_command_t * cmd)
{
  int ret;

  /*
   * Catch unexpected extra arguments on this line. See comment on
   * hicn_cli_node_ctrl_start_set_command_fn
   */
  if (main_input->index > 0 &&
      main_input->buffer[main_input->index - 1] != '\n')
    {
      unformat_input_t _line_input, *line_input = &_line_input;
      if (!unformat_user (main_input, unformat_line_input, line_input))
	{
	  return (0);
	}
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  return clib_error_return (0, "%s '%U'",
				    get_error_string (HICN_ERROR_CLI_INVAL),
				    format_unformat_error, line_input);
	}
    }
  ret = hicn_infra_plugin_enable_disable (0 /* !enable */ ,
					  node_ctl_params.pit_max_size,
					  node_ctl_params.
					  pit_max_lifetime_sec,
					  node_ctl_params.cs_max_size,
					  node_ctl_params.cs_reserved_app);

  return (ret == HICN_ERROR_NONE) ? 0 : clib_error_return (0,
							   get_error_string
							   (ret));
}

#define DFLTD_RANGE_OK(val, min, max)        \
({                        \
    __typeof__ (val) _val = (val);        \
    __typeof__ (min) _min = (min);        \
    __typeof__ (max) _max = (max);        \
    (_val == -1) ||                \
    (_val >= _min && _val <= _max);        \
})

/*
 * cli handler for 'control param'
 */
static clib_error_t *
hicn_cli_node_ctl_param_set_command_fn (vlib_main_t * vm,
					unformat_input_t * main_input,
					vlib_cli_command_t * cmd)
{
  int rv = 0;

  int table_size;
  f64 lifetime;
  int cs_reserved_app;

  if (hicn_main.is_enabled)
    {
      return (clib_error_return
	      (0, "params cannot be altered once hicn started"));
    }
  /* Get a line of input. */
  unformat_input_t _line_input, *line_input = &_line_input;
  if (!unformat_user (main_input, unformat_line_input, line_input))
    {
      return clib_error_return (0,
				get_error_string
				(HICN_ERROR_FWD_ALREADY_ENABLED));
    }
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "pit"))
	{
	  if (unformat (line_input, "size %d", &table_size))
	    {
	      if (!DFLTD_RANGE_OK (table_size, HICN_PARAM_PIT_ENTRIES_MIN,
				   HICN_PARAM_PIT_ENTRIES_MAX))
		{
		  rv = HICN_ERROR_PIT_CONFIG_SIZE_OOB;
		  break;
		}
	      node_ctl_params.pit_max_size = table_size;
	    }
	  else if (unformat (line_input, "maxlife %f", &lifetime))
	    {
	      if (!DFLTD_RANGE_OK
		  (lifetime, HICN_PARAM_PIT_LIFETIME_BOUND_MIN_SEC,
		   HICN_PARAM_PIT_LIFETIME_BOUND_MAX_SEC))
		{
		  rv = HICN_ERROR_PIT_CONFIG_MAXLT_OOB;
		  break;
		}
	      node_ctl_params.pit_max_lifetime_sec = lifetime;
	    }
	  else
	    {
	      rv = HICN_ERROR_CLI_INVAL;
	      break;
	    }
	}
      else if (unformat (line_input, "cs"))
	{
	  if (unformat (line_input, "size %d", &table_size))
	    {
	      if (!DFLTD_RANGE_OK (table_size, HICN_PARAM_CS_ENTRIES_MIN,
				   HICN_PARAM_CS_ENTRIES_MAX))
		{
		  rv = HICN_ERROR_CS_CONFIG_SIZE_OOB;
		  break;
		}
	      node_ctl_params.cs_max_size = table_size;
	    }
	  else if (unformat (line_input, "app %d", &cs_reserved_app))
	    {
	      if (!DFLTD_RANGE_OK (cs_reserved_app, 0, 100))
		{
		  rv = HICN_ERROR_CS_CONFIG_SIZE_OOB;
		  break;
		}
	      node_ctl_params.cs_reserved_app = cs_reserved_app;
	    }
	  else
	    {
	      rv = HICN_ERROR_CLI_INVAL;
	      break;
	    }
	}
      else
	{
	  rv = HICN_ERROR_CLI_INVAL;
	  break;
	}
    }

  if (node_ctl_params.cs_max_size == 0)
    vlib_cli_output (vm,
		     "CS size set to 0. Consider disable CS at compilation time for better performances\n");

  return (rv == HICN_ERROR_NONE) ? 0 : clib_error_return (0, "%s '%U'",
							  get_error_string
							  (rv),
							  format_unformat_error,
							  line_input);
}

/*
 * cli handler for 'hicn show'
 */
static clib_error_t *
hicn_cli_show_command_fn (vlib_main_t * vm, unformat_input_t * main_input,
			  vlib_cli_command_t * cmd)
{
  int face_p = 0, fib_p = 0, all_p, internal_p = 0, strategies_p = 0, ret =
    HICN_ERROR_NONE;

  /* Get a line of input. */
  unformat_input_t _line_input, *line_input = &_line_input;
  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "face all"))
	    {
	      face_p = 1;
	    }
	  else if (unformat (line_input, "internal"))
	    {
	      /*
	       * We consider 'internal' a superset, so
	       * include 'detail' too
	       */
	      internal_p = 1;
	    }
	  else if (unformat (line_input, "strategies"))
	    {
	      /*
	       * We consider 'internal' a superset, so
	       * include 'detail' too
	       */
	      strategies_p = 1;
	    }
	  else
	    {
	      ret = HICN_ERROR_CLI_INVAL;
	      goto done;
	    }
	}
    }
  /* If nothing specified, show everything */
  if ((face_p == 0) && (fib_p == 0) && (strategies_p == 0))
    {
      all_p = 1;
    }
  if (!hicn_main.is_enabled)
    {
      if (node_ctl_params.pit_max_size == -1 &&
	  node_ctl_params.pit_max_lifetime_sec == -1 &&
	  node_ctl_params.cs_max_size == -1 &&
	  node_ctl_params.cs_reserved_app == -1)
	{
	  ret = HICN_ERROR_FWD_NOT_ENABLED;
	  goto done;
	}
      vlib_cli_output (vm, "Forwarder: %sabled\nPreconfiguration:\n",
		       hicn_main.is_enabled ? "en" : "dis");

      if (node_ctl_params.pit_max_size != -1)
	{
	  vlib_cli_output (vm, "  PIT:: max entries:%d\n",
			   node_ctl_params.pit_max_size);
	}
      if (node_ctl_params.pit_max_lifetime_sec != -1)
	{
	  vlib_cli_output (vm, "  PIT:: max lifetime: %05.3f seconds\n",
			   node_ctl_params.pit_max_lifetime_sec);
	}
      if (node_ctl_params.cs_max_size != -1)
	{
	  vlib_cli_output (vm, "  CS:: max entries:%d\n",
			   node_ctl_params.cs_max_size);
	}
      if (node_ctl_params.cs_reserved_app != -1)
	{
	  vlib_cli_output (vm, "  CS:: reserved to app:%d\n",
			   node_ctl_params.cs_reserved_app);
	}
      goto done;
    }
  /* Globals */
  vlib_cli_output (vm,
		   "Forwarder: %sabled\n"
		   "  PIT:: max entries:%d,"
		   " lifetime default: max:%05.3f\n"
		   "  CS::  max entries:%d, network entries:%d, app entries:%d (allocated %d, free %d)\n",
		   hicn_main.is_enabled ? "en" : "dis",
		   hicn_infra_pit_size,
		   ((f64) hicn_main.pit_lifetime_max_ms) / SEC_MS,
		   hicn_infra_cs_size,
		   hicn_infra_cs_size - hicn_main.pitcs.pcs_app_max,
		   hicn_main.pitcs.pcs_app_max,
		   hicn_main.pitcs.pcs_app_count,
		   hicn_main.pitcs.pcs_app_max -
		   hicn_main.pitcs.pcs_app_count);

  vl_api_hicn_api_node_stats_get_reply_t rm = { 0, }
  , *rmp = &rm;
  if (hicn_mgmt_node_stats_get (&rm) == HICN_ERROR_NONE)
    {
      vlib_cli_output (vm,	//compare vl_api_hicn_api_node_stats_get_reply_t_handler block
		       "  PIT entries (now): %d\n"
		       "  CS total entries (now): %d, network entries (now): %d\n"
		       "  Forwarding statistics:\n"
		       "    pkts_processed: %d\n"
		       "    pkts_interest_count: %d\n"
		       "    pkts_data_count: %d\n"
		       "    pkts_from_cache_count: %d\n"
		       "    interests_aggregated: %d\n"
		       "    interests_retransmitted: %d\n",
		       clib_net_to_host_u64 (rmp->pit_entries_count),
		       clib_net_to_host_u64 (rmp->cs_entries_count),
		       clib_net_to_host_u64 (rmp->cs_entries_ntw_count),
		       clib_net_to_host_u64 (rmp->pkts_processed),
		       clib_net_to_host_u64 (rmp->pkts_interest_count),
		       clib_net_to_host_u64 (rmp->pkts_data_count),
		       clib_net_to_host_u64 (rmp->pkts_from_cache_count),
		       clib_net_to_host_u64 (rmp->interests_aggregated),
		       clib_net_to_host_u64 (rmp->interests_retx));
    }
  if (face_p || all_p)
    {
      u8 *strbuf = NULL;

      strbuf = format_hicn_face_all (strbuf, 1, 0);
      vlib_cli_output (vm, "%s", strbuf);

    }
  if (strategies_p || all_p)
    {
      u8 *strbuf = NULL;

      strbuf = format_hicn_strategy_list (strbuf, 1, 0);
      vlib_cli_output (vm, (char *) strbuf);
    }
done:
  if (all_p && internal_p && ret == HICN_ERROR_NONE)
    {
      vlib_cli_output (vm, "Plugin features: cs:%d\n", HICN_FEATURE_CS);
      vlib_cli_output (vm,
		       "Removed CS entries (and freed vlib buffers) %d, Removed PIT entries %d\n",
		       hicn_main.pitcs.pcs_cs_dealloc,
		       hicn_main.pitcs.pcs_pit_dealloc);
      vlib_cli_output (vm,
		       "Bucke count %d, Overflow buckets count %d, used %d\n",
		       hicn_main.pitcs.pcs_table->ht_bucket_count,
		       hicn_main.pitcs.pcs_table->ht_overflow_bucket_count,
		       hicn_main.pitcs.pcs_table->ht_overflow_buckets_used);

    }
  return (ret == HICN_ERROR_NONE) ? 0 : clib_error_return (0, "%s\n",
							   get_error_string
							   (ret));
}

/*
 * cli handler for 'fib'
 */
static clib_error_t *
hicn_cli_fib_set_command_fn (vlib_main_t * vm, unformat_input_t * main_input,
			     vlib_cli_command_t * cmd)
{
  clib_error_t *cl_err = 0;

  int rv = HICN_ERROR_NONE;
  int addpfx = -1;
  ip46_address_t address;
  hicn_face_id_t faceid = HICN_FACE_NULL;
  u32 strategy_id;
  u8 plen = 0;
  fib_prefix_t prefix;

  /* Get a line of input. */
  unformat_input_t _line_input, *line_input = &_line_input;
  if (!unformat_user (main_input, unformat_line_input, line_input))
    {
      return (0);
    }
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (addpfx == -1 && unformat (line_input, "add"))
	{
	  addpfx = 1;
	}
      else if (addpfx == -1 && unformat (line_input, "delete"))
	{
	  addpfx = 0;
	}
      else if (unformat (line_input, "set strategy %d", &strategy_id))
	{
	  addpfx = 2;
	}
      else if (addpfx != -1
	       && unformat (line_input, "prefix %U/%d", unformat_ip46_address,
			    &address, IP46_TYPE_ANY, &plen))
	{;
	}
      else if (addpfx <= 1 && unformat (line_input, "face %u", &faceid))
	{;
	}
      else
	{
	  cl_err = clib_error_return (0, "%s '%U'",
				      get_error_string (HICN_ERROR_CLI_INVAL),
				      format_unformat_error, line_input);
	  goto done;
	}
    }

  fib_prefix_from_ip46_addr (&address, &prefix);
  prefix.fp_len = plen;
  /* Check parse */
  if (addpfx <= 1
      && ((ip46_address_is_zero (&prefix.fp_addr))
	  || faceid == HICN_FACE_NULL))
    {
      cl_err =
	clib_error_return (0, "Please specify prefix and a valid faceid...");
      goto done;
    }
  /* Check parse */
  if ((ip46_address_is_zero (&prefix.fp_addr))
      || (addpfx == 2 && hicn_dpo_strategy_id_is_valid (strategy_id)))
    {
      cl_err = clib_error_return (0,
				  "Please specify prefix and strategy_id...");
      goto done;
    }
  if (addpfx == 0)
    {
      if (ip46_address_is_zero (&prefix.fp_addr))
	{
	  cl_err = clib_error_return (0, "Please specify prefix");
	  goto done;
	}
      if (faceid == HICN_FACE_NULL)
	{
	  rv = hicn_route_del (&prefix);
	}
      else
	{
	  rv = hicn_route_del_nhop (&prefix, faceid);
	}
      cl_err =
	(rv == HICN_ERROR_NONE) ? NULL : clib_error_return (0,
							    get_error_string
							    (rv));

    }
  else if (addpfx == 1)
    {
      rv = hicn_route_add (&faceid, 1, &prefix);
      if (rv == HICN_ERROR_ROUTE_ALREADY_EXISTS)
	{
	  rv = hicn_route_add_nhops (&faceid, 1, &prefix);
	}
      cl_err =
	(rv == HICN_ERROR_NONE) ? NULL : clib_error_return (0,
							    get_error_string
							    (rv));
    }
  else if (addpfx == 2)
    {
      rv = hicn_route_set_strategy (&prefix, strategy_id);
      cl_err =
	(rv == HICN_ERROR_NONE) ? NULL : clib_error_return (0,
							    get_error_string
							    (rv));
    }
done:

  return (cl_err);
}

static clib_error_t *
hicn_cli_punting_command_fn (vlib_main_t * vm, unformat_input_t * main_input,
			     vlib_cli_command_t * cmd)
{
  hicn_mgmt_punting_op_e punting_op = HICN_MGMT_PUNTING_OP_NONE;
  unsigned int subnet_mask = 0;
  ip46_address_t address;
  u32 sw_if_index = ~0;
  int ret = 0;
  vnet_main_t *vnm = NULL;
  u8 type = HICN_PUNT_IP_TYPE;
  u32 src_port = HICN_PUNT_INVALID_PORT, dst_port = HICN_PUNT_INVALID_PORT;
  vnm = vnet_get_main ();
  u8 sport = 0;
  u8 dport = 0;
  fib_prefix_t prefix;

  unformat_input_t _line_input, *line_input = &_line_input;
  if (!unformat_user (main_input, unformat_line_input, line_input))
    {
      return (0);
    }
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	{
	  punting_op = HICN_MGMT_PUNTING_OP_CREATE;
	}
      else if (unformat (line_input, "delete"))
	{
	  punting_op = HICN_MGMT_PUNTING_OP_DELETE;
	}
      else if (unformat (line_input, "intfc %U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	{;
	}
      else if (unformat
	       (line_input, "prefix %U/%d", unformat_ip46_address,
		&address, IP46_TYPE_ANY, &subnet_mask))
	{;
	}
      else if (unformat (line_input, "type ip"))
	{
	  type = HICN_PUNT_IP_TYPE;
	}
      else if (unformat (line_input, "type"))
	{
	  if (unformat (line_input, "udp4"))
	    {
	      type = HICN_PUNT_UDP4_TYPE;
	    }
	  else if (unformat (line_input, "udp6"))
	    {
	      type = HICN_PUNT_UDP6_TYPE;
	    }

	  if (unformat (line_input, "src_port %u", &src_port))
	    {
		  sport = 1;
		}
	  if (unformat (line_input, "dst_port %u", &dst_port))
	    {
		  dport = 1;
		}
	}
      else
	{
	  return (clib_error_return (0, "invalid option"));
	}
    }

  fib_prefix_from_ip46_addr(&address, &prefix);
  prefix.fp_len = subnet_mask;
  if (punting_op == HICN_MGMT_PUNTING_OP_CREATE
      && (ip46_address_is_zero (&prefix.fp_addr) || sw_if_index == ~0))
    {
      return (clib_error_return
	      (0, "Please specify valid prefix and interface"));
    }
  else if ((punting_op == HICN_MGMT_PUNTING_OP_DELETE) &&
	   ip46_address_is_zero (&prefix.fp_addr))
    {
      return (clib_error_return
	      (0, "Please specify valid prefix and optionally an interface"));
    }
  else if (punting_op == HICN_MGMT_PUNTING_OP_NONE)
    {
      return (clib_error_return
	      (0, "Please specify valid operation, add or delete"));
    }
  switch (punting_op)
    {
    case HICN_MGMT_PUNTING_OP_CREATE:
      {
	if (type == HICN_PUNT_UDP4_TYPE || type == HICN_PUNT_UDP6_TYPE)
	  {
	    if (sport != 0 || dport != 0)
	      ret =
		hicn_punt_interest_data_for_udp (vm, &prefix,
						 sw_if_index, type,
						 clib_host_to_net_u16
						 (src_port),
						 clib_host_to_net_u16
						 (dst_port), NO_L2);
	    else
	      return (clib_error_return
		      (0,
		       "Please specify valid source and destination udp port"));
	  }
	else
	  {
	    ret =
	      hicn_punt_interest_data_for_ip (vm, &prefix, sw_if_index, type, NO_L2);
	  }
      }
      break;
    case HICN_MGMT_PUNTING_OP_DELETE:
      {
	if (sw_if_index != ~0)
	  {
	    ip46_address_is_ip4 (&prefix.fp_addr) ?
	      hicn_punt_enable_disable_vnet_ip4_table_on_intf (vm,
							       sw_if_index,
							       0) :
	      hicn_punt_enable_disable_vnet_ip6_table_on_intf (vm,
							       sw_if_index,
							       0);
	  }
	else if (!(ip46_address_is_zero (&prefix.fp_addr)))
	  {
	    ret = ip46_address_is_ip4 (&prefix.fp_addr) ?
	      hicn_punt_remove_ip4_address (vm, &prefix, 1,
					    sw_if_index,
					    0, NO_L2) :
	      hicn_punt_remove_ip6_address (vm, &prefix, 1, sw_if_index, 0,
					    NO_L2);
	  }
      }
      break;
    default:
      break;
    }

  return (ret == HICN_ERROR_NONE) ? 0 : clib_error_return (0,
							   get_error_string
							   (ret));
}

/*
 * cli handler for 'pgen'
 */
static clib_error_t *
hicn_cli_pgen_client_set_command_fn (vlib_main_t * vm,
				     unformat_input_t * main_input,
				     vlib_cli_command_t * cmd)
{
  hicnpg_main_t *hpgm = &hicnpg_main;
  ip46_address_t src_addr;
  fib_prefix_t *prefix = malloc (sizeof (fib_prefix_t));
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u16 lifetime = 4000;
  int rv = VNET_API_ERROR_UNIMPLEMENTED;
  u32 max_seq = ~0;
  u32 n_flows = ~0;
  u32 n_ifaces = 1;

  /* Get a line of input. */
  unformat_input_t _line_input, *line_input = &_line_input;
  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat
	      (line_input, "intfc %U", unformat_vnet_sw_interface, vnm,
	       &sw_if_index))
	    {
	      ;
	    }
	  else if (unformat (line_input, "src %U",
			     unformat_ip46_address, &src_addr))
	    {
	      ;
	    }
	  else if (unformat (line_input, "n_ifaces %d", &n_ifaces))
	    {
	      ;
	    }
	  else if (unformat (line_input, "name %U/%d",
			     unformat_ip46_address, &prefix->fp_addr,
			     IP46_TYPE_ANY, &prefix->fp_len))
	    {
	      ;
	    }
	  else if (unformat (line_input, "lifetime %d", &lifetime))
	    {
	      ;
	    }
	  else if (unformat (line_input, "max_seq %d", &max_seq))
	    {
	      ;
	    }
	  else if (unformat (line_input, "n_flows %d", &n_flows))
	    {
	      ;
	    }
	  else
	    {
	      return (clib_error_return
		      (0, "Unknown input '%U'", format_unformat_error,
		       line_input));
	      break;
	    }
	}
    }
  hpgm->interest_lifetime = lifetime;

  if (sw_if_index == ~0)
    {
      return (clib_error_return (0, "Packet generator interface missing"));
    }

  //Remove bits that are out of the subnet
  if (ip46_address_is_ip4 (&prefix->fp_addr))
    {
      ip4_address_t mask;
      ip4_preflen_to_mask (prefix->fp_len, &mask);
      prefix->fp_addr.ip4.as_u32 = prefix->fp_addr.ip4.as_u32 & mask.as_u32;
      prefix->fp_proto = FIB_PROTOCOL_IP4;
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
    }

  /*
   * Enable the feature to divert data packet to the hicnpg-data node to count
   * how many data packets have been received.
   * Diver all the packets from the packet-generator to the hicn-pg-interest node
   * to generate valid interests.
   */
  if (ip46_address_is_ip4 (&src_addr)
      && ip46_address_is_ip4 (&prefix->fp_addr))
    {
      prefix->fp_proto = FIB_PROTOCOL_IP4;

      vnet_feature_enable_disable ("ip4-unicast", "hicnpg-data",
				   sw_if_index, 1, 0, 0);

      /* Add pgen_client node to the vpp graph */
      vlib_node_add_next (vm,
			  pg_input_node.index, hicn_pg_interest_node.index);


      pg_node_t *pn;
      pn = pg_get_node (hicn_pg_interest_node.index);
      pn->unformat_edit = unformat_pg_ip4_header;

    }
  else if (!ip46_address_is_ip4 (&src_addr)
	   && !ip46_address_is_ip4 (&prefix->fp_addr))
    {
      prefix->fp_proto = FIB_PROTOCOL_IP6;

      vnet_feature_enable_disable ("ip6-unicast", "hicnpg-data",
				   sw_if_index, 1, 0, 0);

      /* Add pgen_client node to the vpp graph */
      vlib_node_add_next (vm, pg_input_node.index,
			  hicn_pg_interest_node.index);

      pg_node_t *pn;
      pn = pg_get_node (hicn_pg_interest_node.index);
      pn->unformat_edit = unformat_pg_ip6_header;
    }
  else
    {
      return (clib_error_return
	      (0,
	       "pg interface source address, source address and hicn name must be of the same type IPv4 or IPv6"));
    }


  hpgm->pgen_clt_src_addr = src_addr;
  hpgm->pgen_clt_hicn_name = prefix;
  hpgm->max_seq_number = max_seq;
  hpgm->n_flows = n_flows;
  hpgm->n_ifaces = n_ifaces;
  hpgm->sw_if = sw_if_index;
  vlib_cli_output (vm, "ifaces %d", hpgm->n_ifaces);
  rv = 0;

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0, "Unimplemented, NYI");
      break;

    default:
      return clib_error_return (0, "hicn enable_disable returned %d", rv);
    }

  return 0;
}

/*
 * cli handler for 'pgen'
 */
static clib_error_t *
hicn_cli_pgen_server_set_command_fn (vlib_main_t * vm,
				     unformat_input_t * main_input,
				     vlib_cli_command_t * cmd)
{
  clib_error_t *cl_err;
  int rv = HICN_ERROR_NONE;
  hicnpg_server_main_t *pg_main = &hicnpg_server_main;
  int payload_size = 1440;
  u32 sw_if_index = ~0;
  vnet_main_t *vnm = vnet_get_main ();
  fib_prefix_t *prefix = calloc (1, sizeof (fib_prefix_t));

  /* Get a line of input. */
  unformat_input_t _line_input, *line_input = &_line_input;
  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      /* Parse the arguments */
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "name %U/%d",
			unformat_ip46_address, &prefix->fp_addr,
			IP46_TYPE_ANY, &prefix->fp_len))
	    {;
	    }
	  else if (unformat (line_input, "size %d", &payload_size))
	    {
	      if (payload_size > 1440)
		{
		  return (clib_error_return (0,
					     "Payload size must be <= 1440 bytes..."));
		}
	    }
	  else
	    if (unformat
		(line_input, "intfc %U", unformat_vnet_sw_interface, vnm,
		 &sw_if_index))
	    {
	      ;
	    }
	  else
	    {
	      return (clib_error_return
		      (0, "Unknown input '%U'", format_unformat_error,
		       line_input));
	      break;
	    }
	}
    }

  /* Attach our packet-gen node for ip4 udp local traffic */
  if ((prefix->fp_addr.ip6.as_u64[0] == (u64) 0
       && prefix->fp_addr.ip6.as_u64[1] == 0) || payload_size == 0
      || sw_if_index == ~0)
    {
      return clib_error_return (0,
				"Error: must supply local port, payload size and incoming hICN prefix");
    }

  //Remove bits that are out of the subnet
  if (ip46_address_is_ip4 (&prefix->fp_addr))
    {
      ip4_address_t mask;
      ip4_preflen_to_mask (prefix->fp_len, &mask);
      prefix->fp_addr.ip4.as_u32 = prefix->fp_addr.ip4.as_u32 & mask.as_u32;
      prefix->fp_proto = FIB_PROTOCOL_IP4;
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
    }

  /* Allocate the buffer with the actual content payload TLV */
  vlib_buffer_alloc (vm, &pg_main->pgen_svr_buffer_idx, 1);
  vlib_buffer_t *rb = NULL;
  rb = vlib_get_buffer (vm, pg_main->pgen_svr_buffer_idx);

  pg_main->pgen_srv_hicn_name = prefix;

  /* Initialize the buffer data with zeros */
  memset (rb->data, 0, payload_size);
  rb->current_length = payload_size;

  vnet_feature_enable_disable ("ip4-unicast", "hicnpg-server",
			       sw_if_index, 1, 0, 0);
  vnet_feature_enable_disable ("ip6-unicast", "hicnpg-server",
			       sw_if_index, 1, 0, 0);

  switch (rv)
    {
    case 0:
      cl_err = 0;
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      cl_err = clib_error_return (0, "Unimplemented, NYI");
      break;

    default:
      cl_err = clib_error_return (0, "hicn pgen server returned %d", rv);
    }

  return cl_err;
}

/* cli declaration for 'control start' */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND(hicn_cli_node_ctl_start_set_command, static)=
{
	.path = "hicn control start",
        .short_help = "hicn control start",
        .function = hicn_cli_node_ctl_start_set_command_fn,
};


/* cli declaration for 'control stop' */
VLIB_CLI_COMMAND(hicn_cli_node_ctl_stop_set_command, static)=
{
	.path = "hicn control stop",
        .short_help = "hicn control stop",
        .function = hicn_cli_node_ctl_stop_set_command_fn,
};


/* cli declaration for 'control param' */
VLIB_CLI_COMMAND(hicn_cli_node_ctl_param_set_command, static)=
{
	.path = "hicn control param",
        .short_help = "hicn control param { pit { size <entries> | { dfltlife | minlife | maxlife } <seconds> } | fib size <entries> | cs {size <entries> | app <portion to reserved to app>} }\n",
        .function = hicn_cli_node_ctl_param_set_command_fn,
};

/* cli declaration for 'control' (root path of multiple commands, for help) */
VLIB_CLI_COMMAND(hicn_cli_node_ctl_command, static)=
{
	.path = "hicn control",
        .short_help = "hicn control"
};

/* cli declaration for 'fib' */
VLIB_CLI_COMMAND(hicn_cli_fib_set_command, static)=
{
	.path = "hicn fib",
        .short_help = "hicn fib {{add | delete } prefix <prefix> face <facei_d> }"
        " | set strategy <strategy_id> prefix <prefix>",
        .function = hicn_cli_fib_set_command_fn,
};

/* cli declaration for 'show' */
VLIB_CLI_COMMAND(hicn_cli_show_command, static)=
{
	.path = "hicn show",
        .short_help = "hicn show "
        "[internal]"
        "[strategies]",
        .function = hicn_cli_show_command_fn,
};

/* cli declaration for 'punting' */
VLIB_CLI_COMMAND(hicn_cli_punting_command, static)=
  {
   .path = "hicn punting",
   .short_help = "hicn punting {add|delete} prefix <prefix> intfc <sw_if> {type ip | type <udp4|udp6> src_port <port> dst_port <port>}",
   .function = hicn_cli_punting_command_fn,
  };

/* cli declaration for 'hicn pgen client' */
VLIB_CLI_COMMAND(hicn_cli_pgen_client_set_command, static)=
{
	.path = "hicn pgen client",
        .short_help = "hicn pgen client src <src_addr> name <prefix> { n_ifaces <n_ifaces> lifetime <interest-lifetime> intfc <data in-interface> max_seq <max sequence number> n_flows <number of flows>}",
        .long_help = "Run hicn in packet-gen client mode\n",
        .function = hicn_cli_pgen_client_set_command_fn,
};

/* cli declaration for 'hicn pgen client' */
VLIB_CLI_COMMAND(hicn_cli_pgen_server_set_command, static)=
{
	.path = "hicn pgen server",
        .short_help = "hicn pgen server name <prefix> intfc <interest in-interface> size <payload_size>",
        .long_help = "Run hicn in packet-gen server mode\n",
        .function = hicn_cli_pgen_server_set_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
