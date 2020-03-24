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

#include <hicn_hs/hicn_hs.h>
#include <hicn_hs/hicn_hs_route.h>

#include <vnet/session/session.h>

static clib_error_t *
hicn_hs_enable_disable_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_en = 1;
  clib_error_t *error;

  session_cli_return_if_not_enabled ();

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected enable | disable");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
	is_en = 1;
      else if (unformat (line_input, "disable"))
	is_en = 0;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  unformat_free (line_input);
	  return error;
	}
    }

  unformat_free (line_input);
  return hicn_hs_enable_disable (vm, is_en);
}

static clib_error_t *
hicn_hs_set_local_prefix_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  fib_prefix_t prefix;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected ip_address/prefix_len");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U/%d", unformat_ip46_address,
		    &prefix.fp_addr, IP46_TYPE_ANY, &prefix.fp_len))
	{
	  prefix.fp_proto = ip46_address_is_ip4(&prefix.fp_addr) ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
	  error = hicn_hs_set_local_prefix(&prefix);
	}
      else
        {
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	}
    }

  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (hicn_hs_onoff, static) =
{
  .path = "hicn hs",
  .short_help = "hicn hs [enable|disable]",
  .function = hicn_hs_enable_disable_fn,
};

VLIB_CLI_COMMAND(hicn_hs_set_local_pfx, static) =
{
  .path = "hicn hs set local prefix",
  .short_help = "hicn hs set local prefix <ip_prefix/plen>",
  .function = hicn_hs_set_local_prefix_fn,
};
/* *INDENT-ON* */