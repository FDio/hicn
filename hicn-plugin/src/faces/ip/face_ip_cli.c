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

#include "face_ip.h"
#include "dpo_ip.h"
#include "../face.h"

#define HICN_FACE_NONE 0
#define HICN_FACE_DELETE 1
#define HICN_FACE_ADD 2

static clib_error_t *
hicn_face_ip_cli_set_command_fn (vlib_main_t * vm,
				 unformat_input_t * main_input,
				 vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip46_address_t local_addr;
  ip46_address_t remote_addr;
  hicn_face_id_t face_id = HICN_FACE_NULL;
  int app_face = 0;
  u32 cs_reserved = HICN_PARAM_FACE_DFT_CS_RESERVED;
  int ret = HICN_ERROR_NONE;
  int sw_if;
  int face_op = HICN_FACE_NONE;

  ip46_address_reset (&local_addr);
  /* Get a line of input. */
  unformat_input_t _line_input, *line_input = &_line_input;
  if (!unformat_user (main_input, unformat_line_input, line_input))
    {
      return (0);
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	{
	  if (unformat (line_input, "id %d", &face_id))
	    face_op = HICN_FACE_DELETE;
	  else
	    {
	      return clib_error_return (0, "missing face id");
	    }
	}
      else if (unformat (line_input, "add"))
	{
	  face_op = HICN_FACE_ADD;
	  if (unformat (line_input, "local %U remote %U intfc %U",
			unformat_ip46_address, &local_addr, IP46_TYPE_ANY,
			unformat_ip46_address, &remote_addr, IP46_TYPE_ANY,
			unformat_vnet_sw_interface, vnm, &sw_if));
	  else
	    {
	      return clib_error_return (0, "%s '%U'",
					get_error_string
					(HICN_ERROR_CLI_INVAL),
					format_unformat_error, line_input);
	    }
	}
      else if (unformat (line_input, "app_face %d", &app_face))
	{
	  if (unformat (line_input, "cs_size %d", &cs_reserved));
	}
      else
	{
	  return clib_error_return (0, "%s '%U'",
				    get_error_string (HICN_ERROR_CLI_INVAL),
				    format_unformat_error, line_input);
	}
    }

  if (face_id != HICN_FACE_NULL)
    {

      if (!hicn_dpoi_idx_is_valid (face_id))
	{
	  return clib_error_return (0, "%s, face_id %d not valid",
				    get_error_string (ret), face_id);
	}
    }

  int rv;
  switch (face_op)
    {
    case HICN_FACE_ADD:

      /* Check for presence of next hop address */
      if ((remote_addr.as_u64[0] == (u64) 0)
	  && (remote_addr.as_u64[1] == (u64) 0))
	{
	  return clib_error_return (0, "next hop address not specified");
	}

      rv = hicn_face_ip_add (&local_addr, &remote_addr, sw_if, &face_id);

      if (rv == HICN_ERROR_NONE)
	{
	  vlib_cli_output (vm, "Face id: %d", face_id);
	}
      else
	{
	  return clib_error_return (0, get_error_string (rv));
	}
      break;
    case HICN_FACE_DELETE:
      rv = hicn_face_ip_del (face_id);
      if (rv == HICN_ERROR_NONE)
	{
	  vlib_cli_output (vm, "Face %d deleted", face_id);
	}
      else
	{
	  return clib_error_return (0, get_error_string (rv));
	}
      break;
    default:
      return clib_error_return (0, "Operation (%d) not implemented", face_op);
      break;
    }
  return (rv == HICN_ERROR_NONE) ? 0 : clib_error_return (0, "%s\n",
							  get_error_string
							  (rv));
}

/* cli declaration for 'cfg face' */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (hicn_face_ip_cli_set_command, static) =
{
  .path = "hicn face ip",
  .short_help = "hicn face ip {add local <local_address> remote <remote_address> intfc <sw_if>} {app_face <0/1>} {cs_size <size_in_packets>} | {del id <face_id>}",
  .function = hicn_face_ip_cli_set_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
