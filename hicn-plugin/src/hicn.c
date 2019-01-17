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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>

#include "hicn.h"
#include "params.h"
#include "infra.h"
#include "strategy_dpo_manager.h"
#include "mgmt.h"
#include "punt.h"
#include "error.h"
#include "faces/app/address_mgr.h"
#include "face_db.h"
#include "faces/udp/face_udp.h"

hicn_main_t hicn_main;
/* Module vars */
int hicn_infra_fwdr_initialized = 0;

/*
 * Global time counters we're trying out for opportunistic hashtable
 * expiration.
 */
uint16_t hicn_infra_fast_timer;	/* Counts at 1 second intervals */
uint16_t hicn_infra_slow_timer;	/* Counts at 1 minute intervals */

hicn_face_bucket_t *hicn_face_bucket_pool;

/*
 * Init hicn forwarder with configurable PIT, CS sizes
 */
static int
hicn_infra_fwdr_init (uint32_t shard_pit_size, uint32_t shard_cs_size,
		      uint32_t cs_reserved)
{
  int ret = 0;

  if (hicn_infra_fwdr_initialized)
    {
      ret = HICN_ERROR_FWD_ALREADY_ENABLED;
      goto done;
    }
  /* Init per worker limits */
  hicn_infra_pit_size = shard_pit_size;
  hicn_infra_cs_size = shard_cs_size;

  /* Init the global time-compression counters */
  hicn_infra_fast_timer = 1;
  hicn_infra_slow_timer = 1;

  ret = hicn_pit_create (&hicn_main.pitcs, hicn_infra_pit_size);
  hicn_pit_set_lru_max (&hicn_main.pitcs,
			hicn_infra_cs_size -
			(hicn_infra_cs_size * cs_reserved / 100));
  hicn_pit_set_lru_app_max (&hicn_main.pitcs,
			    hicn_infra_cs_size * cs_reserved / 100);

done:
  if ((ret == HICN_ERROR_NONE) && !hicn_infra_fwdr_initialized)
    {
      hicn_infra_fwdr_initialized = 1;
    }
  return (ret);
}

/*
 * Action function shared between message handler and debug CLI NOTICE: we're
 * only 'enabling' now
 */
int
hicn_infra_plugin_enable_disable (int enable_disable,
				  int pit_size_req,
				  f64 pit_dflt_lifetime_sec_req,
				  f64 pit_min_lifetime_sec_req,
				  f64 pit_max_lifetime_sec_req,
				  int cs_size_req, int cs_reserved_app)
{
  int ret = 0;

  hicn_main_t *sm = &hicn_main;
  uint32_t pit_size, cs_size, cs_reserved;

  /* Notice if we're already enabled... */
  if (sm->is_enabled)
    {
      ret = HICN_ERROR_FWD_ALREADY_ENABLED;
      goto done;
    }
  /* Set up params and call fwdr_init set up PIT/CS, forwarder nodes */

  /* Check the range and assign some globals */
  if (pit_min_lifetime_sec_req < 0)
    {
      sm->pit_lifetime_min_ms = HICN_PARAM_PIT_LIFETIME_DFLT_MIN_MS;
    }
  else
    {
      if (pit_min_lifetime_sec_req < HICN_PARAM_PIT_LIFETIME_BOUND_MIN_SEC ||
	  pit_min_lifetime_sec_req > HICN_PARAM_PIT_LIFETIME_BOUND_MAX_SEC)
	{
	  ret = HICN_ERROR_PIT_CONFIG_MINLT_OOB;
	  goto done;
	}
      sm->pit_lifetime_min_ms = pit_min_lifetime_sec_req * SEC_MS;
    }

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
  if (sm->pit_lifetime_min_ms > sm->pit_lifetime_max_ms)
    {
      ret = HICN_ERROR_PIT_CONFIG_MINMAXLT;
      goto done;
    }
  if (pit_dflt_lifetime_sec_req < 0)
    {
      sm->pit_lifetime_dflt_ms = HICN_PARAM_PIT_LIFETIME_DFLT_DFLT_MS;
    }
  else
    {
      sm->pit_lifetime_dflt_ms = pit_dflt_lifetime_sec_req * SEC_MS;
    }
  if (sm->pit_lifetime_dflt_ms < sm->pit_lifetime_min_ms ||
      sm->pit_lifetime_dflt_ms > sm->pit_lifetime_max_ms)
    {
      ret = HICN_ERROR_PIT_CONFIG_DFTLT_OOB;
      goto done;
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
      if (cs_size_req > HICN_PARAM_CS_ENTRIES_MAX)
	{
	  ret = HICN_ERROR_CS_CONFIG_SIZE_OOB;
	  goto done;
	}
      cs_size = (uint32_t) cs_size_req;
    }

  if (cs_reserved_app < 0)
    {
      cs_reserved = HICN_PARAM_CS_RESERVED_APP;
    }
  else
    {
      if (cs_reserved_app >= 100)
	ret = HICN_ERROR_CS_CONFIG_RESERVED_OOB;
      cs_reserved = cs_reserved_app;
    }

  ret = hicn_infra_fwdr_init (pit_size, cs_size, cs_reserved);

  hicn_face_db_init (pit_size);

  if (ret != HICN_ERROR_NONE)
    {
      goto done;
    }
  sm->is_enabled = 1;

  hicn_face_udp_init_internal ();

done:

  return (ret);
}

/*
 * Init entry-point for the icn plugin
 */
static clib_error_t *
hicn_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;

  hicn_main_t *sm = &hicn_main;

  /* Init other elements in the 'main' struct */
  sm->is_enabled = 0;

  error = hicn_api_plugin_hookup (vm);

  /* Init the hash table */
  hicn_punt_init (vm);

  /* Init the dpo module */
  hicn_dpos_init ();

  /* Init the app manager */
  address_mgr_init ();

  hicn_face_module_init (vm);

  return error;
}

VLIB_INIT_FUNCTION (hicn_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER() =
{
	.description = "hICN forwarder"
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
