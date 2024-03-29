/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vlib/vlib.h>
#include <vnet/interface.h>

#include "hicn.h"
#include "params.h"
#include "infra.h"
#include "strategy_dpo_manager.h"
#include "mgmt.h"
#include "error.h"
#include "faces/app/address_mgr.h"
#include "udp_tunnels/udp_tunnel.h"
#include "route.h"
#include "pg.h"

hicn_main_t hicn_main;
/* Module vars */
int hicn_infra_fwdr_initialized = 0;

// hicn_face_bucket_t *hicn_face_bucket_pool;

/*
 * Init hicn forwarder with configurable PIT, CS sizes
 */
static int
hicn_infra_fwdr_init (uint32_t shard_pit_size, uint32_t shard_cs_size)
{
  int ret = HICN_ERROR_NONE;

  if (hicn_infra_fwdr_initialized)
    {
      ret = HICN_ERROR_FWD_ALREADY_ENABLED;
      goto DONE;
    }

  /* Init per worker limits */
  hicn_infra_pit_size = shard_pit_size;
  hicn_infra_cs_size = shard_cs_size;

  hicn_pit_create (&hicn_main.pitcs, hicn_infra_pit_size, hicn_infra_cs_size);

DONE:
  if ((ret == HICN_ERROR_NONE) && !hicn_infra_fwdr_initialized)
    {
      hicn_infra_fwdr_initialized = 1;
    }

  return ret;
}

/*
 * Action function shared between message handler and debug CLI NOTICE: we're
 * only 'enabling' now
 */
int
hicn_infra_plugin_enable_disable (int enable_disable, int pit_size_req,
				  f64 pit_max_lifetime_sec_req,
				  int cs_size_req, vnet_link_t link)
{
  int ret = 0;

  hicn_main_t *sm = &hicn_main;
  uint32_t pit_size, cs_size;

  /* Notice if we're already enabled... */
  if (sm->is_enabled)
    {
      ret = HICN_ERROR_FWD_ALREADY_ENABLED;
      goto done;
    }
  /* Set up params and call fwdr_init set up PIT/CS, forwarder nodes */

  /* Check the range and assign some globals */
  if (pit_max_lifetime_sec_req < 0)
    {
      sm->pit_lifetime_max_ms = HICN_PARAM_PIT_LIFETIME_DFLT_MAX_MS;
    }
  else
    {
      if (pit_max_lifetime_sec_req < HICN_PARAM_PIT_LIFETIME_BOUND_MIN_SEC ||
	  pit_max_lifetime_sec_req > HICN_PARAM_PIT_LIFETIME_BOUND_MAX_SEC)
	{
	  ret = HICN_ERROR_PIT_CONFIG_MAXLT_OOB;
	  goto done;
	}
      sm->pit_lifetime_max_ms = pit_max_lifetime_sec_req * SEC_MS;
    }

  if (pit_size_req < 0)
    {
      pit_size = HICN_PARAM_PIT_ENTRIES_DFLT;
    }
  else
    {
      if (pit_size_req < HICN_PARAM_PIT_ENTRIES_MIN ||
	  pit_size_req > HICN_PARAM_PIT_ENTRIES_MAX)
	{
	  ret = HICN_ERROR_PIT_CONFIG_SIZE_OOB;
	  goto done;
	}
      pit_size = (uint32_t) pit_size_req;
    }

  if (cs_size_req < 0)
    {
      cs_size = HICN_PARAM_CS_ENTRIES_DFLT;
    }
  else
    {
      /*
       * This should be relatively safe
       * At this point vlib buffers should have been already allocated
       */

      vlib_buffer_main_t *bm;
      vlib_buffer_pool_t *bp;
      vlib_main_t *vm = vlib_get_main ();
      bm = vm->buffer_main;

      u32 n_buffers = 0;
      vec_foreach (bp, bm->buffer_pools)
	n_buffers = n_buffers < bp->n_buffers ? bp->n_buffers : n_buffers;

      // check if CS is bugger tha PIT or bigger than the available
      // vlib_buffers
      uword cs_buffers = (n_buffers > HICN_PARAM_CS_MIN_MBUF) ?
				 n_buffers - HICN_PARAM_CS_MIN_MBUF :
				 0;

      if (cs_size_req > (pit_size_req / 2) || cs_size_req > cs_buffers)
	{
	  cs_size_req =
	    ((pit_size_req / 2) > cs_buffers) ? cs_buffers : pit_size_req / 2;
	  vlib_cli_output (vm,
			   "WARNING!! CS too large. Please check size of PIT "
			   "or the number of buffers available in VPP\n");
	}
      cs_size = (uint32_t) cs_size_req;
    }

  ret = hicn_infra_fwdr_init (pit_size, cs_size);

  if (ret != HICN_ERROR_NONE)
    {
      goto done;
    }
  sm->is_enabled = 1;
  sm->link = link;
  // hicn_face_udp_init_internal ();

done:

  return (ret);
}

static clib_error_t *
hicn_configure (vlib_main_t *vm, unformat_input_t *input)
{
  u32 pit_size = HICN_PARAM_PIT_ENTRIES_DFLT;
  u32 cs_size = HICN_PARAM_CS_ENTRIES_DFLT;
  u64 pit_lifetime_max_sec = HICN_PARAM_PIT_LIFETIME_DFLT_MAX_MS / SEC_MS;

  vnet_link_t link;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "pit-size %u", &pit_size))
	;
      else if (unformat (input, "cs-size %u", &cs_size))
	;
      else if (unformat (input, "pit-lifetime-max %u", &pit_lifetime_max_sec))
	;
      else if (unformat (input, "grab mpls-tunnels"))
	link = VNET_LINK_MPLS;
      else
	break;
    }

  unformat_free (input);

  hicn_infra_plugin_enable_disable (1, pit_size, pit_lifetime_max_sec, cs_size,
				    link);

  return 0;
}

VLIB_CONFIG_FUNCTION (hicn_configure, "hicn");

/*
 * Init entry-point for the icn plugin
 */
static clib_error_t *
hicn_init (vlib_main_t *vm)
{
  clib_error_t *error = 0;

  hicn_main_t *sm = &hicn_main;

  // Init other elements in the 'main' struct
  sm->is_enabled = 0;

  error = hicn_api_plugin_hookup (vm);

  // Init the dpo module
  hicn_dpos_init ();

  // Init the app manager
  address_mgr_init ();

  // Init the face module
  hicn_face_module_init (vm);

  // Init the route module
  hicn_route_init ();

  // Init the UDP tunnels module
  udp_tunnel_init ();

  // Init the packet generator module
  hicn_pg_init (vm);

  return error;
}

VLIB_INIT_FUNCTION (hicn_init);

VLIB_PLUGIN_REGISTER () = { .description = "hICN forwarder" };

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
