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
#include <vnet/dpo/dpo.h>
#include <vlib/vlib.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>

#include "../strategy_dpo_manager.h"
#include "../faces/face.h"
#include "../error.h"
#include "../route.h"
#include "dpo_mw.h"

static clib_error_t *
hicn_mw_strategy_cli_set_weight_command_fn (vlib_main_t * vm,
					    unformat_input_t * main_input,
					    vlib_cli_command_t * cmd)
{
  clib_error_t *cl_err = 0;
  int ret = HICN_ERROR_NONE;
  ip46_address_t prefix;
  hicn_face_id_t faceid = HICN_FACE_NULL;
  u32 fib_index;
  u32 weight = HICN_PARAM_FIB_ENTRY_NHOP_WGHT_DFLT;
  u32 plen = 0;
  hicn_dpo_ctx_t *hicn_dpo_ctx;
  const dpo_id_t *hicn_dpo_id;
  u32 vft_id;
  const hicn_dpo_vft_t *dpo_vft;

  /* Get a line of input. */
  unformat_input_t _line_input, *line_input = &_line_input;
  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "prefix %U/%u", unformat_ip46_address,
			&prefix, IP46_TYPE_ANY, &plen))
	    ;
	  else if (unformat (line_input, "face %u", &faceid))
	    ;
	  else if (unformat (line_input, "weight %u", &weight))
	    ;
	  else
	    {
	      return clib_error_return (0, "%s",
					get_error_string
					(HICN_ERROR_CLI_INVAL));
	    }

	}
    }

  if (((weight < 0) || (weight > HICN_PARAM_FIB_ENTRY_NHOP_WGHT_MAX)))
    {
      cl_err = clib_error_return (0,
				  "Next-hop weight must be between 0 and %d",
				  (int) HICN_PARAM_FIB_ENTRY_NHOP_WGHT_MAX);
      goto done;
    }

  if (((ip46_address_is_zero (&prefix)) || faceid == HICN_FACE_NULL))
    {
      cl_err =
	clib_error_return (0, "Please specify prefix and a valid faceid...");
      goto done;
    }

  fib_prefix_t fib_pfx;
  fib_prefix_from_ip46_addr (&prefix, &fib_pfx);
  fib_pfx.fp_len = plen;

  ret = hicn_route_get_dpo (&prefix, plen, &hicn_dpo_id, &fib_index);

  if (ret == HICN_ERROR_NONE)
    {
      vft_id = hicn_dpo_get_vft_id (hicn_dpo_id);
      dpo_vft = hicn_dpo_get_vft (vft_id);
      hicn_dpo_ctx = dpo_vft->hicn_dpo_get_ctx (hicn_dpo_id->dpoi_index);

      if (hicn_dpo_ctx == NULL
	  || hicn_dpo_id->dpoi_type != hicn_dpo_strategy_mw_get_type ())
	{
	  cl_err = clib_error_return (0, get_error_string (ret));
	  goto done;
	}

      hicn_strategy_mw_ctx_t *mw_dpo =
	(hicn_strategy_mw_ctx_t *) hicn_dpo_ctx;
      int idx = ~0;
      for (int i = 0; i < hicn_dpo_ctx->entry_count; i++)
	if (hicn_dpo_ctx->next_hops[i].dpoi_index == (index_t) faceid)
	  idx = i;

      if (idx == ~0)
	{
	  cl_err =
	    clib_error_return (0,
			       get_error_string
			       (HICN_ERROR_MW_STRATEGY_NH_NOT_FOUND));
	  goto done;
	}

      mw_dpo->weight[idx] = weight;
    }
  else
    {
      cl_err = clib_error_return (0, get_error_string (ret));

    }

done:

  return (cl_err);

}

/* cli declaration for 'strategy mw' */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND(hicn_mw_strategy_cli_set_weight_command, static)=
{
  .path = "hicn strategy mw set",
  .short_help = "hicn strategy mw set prefix <prefix> face <face_id> weight <weight>",
  .function = hicn_mw_strategy_cli_set_weight_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
