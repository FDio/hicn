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
#include <vnet/ip/ip6_packet.h>

//#include "../face_dpo.h"
#include "../face.h"
#include "face_prod.h"
#include "face_cons.h"

#define HICN_FACE_NONE 0
#define HICN_FACE_DELETE 1
#define HICN_FACE_ADD 2

static clib_error_t *
hicn_face_app_cli_set_command_fn (vlib_main_t * vm,
				  unformat_input_t * main_input,
				  vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  fib_prefix_t prefix;
  hicn_face_id_t face_id1 = HICN_FACE_NULL;
  hicn_face_id_t face_id2 = HICN_FACE_NULL;
  u32 cs_reserved = HICN_PARAM_FACE_DFT_CS_RESERVED;
  int ret = HICN_ERROR_NONE;
  int sw_if;
  int face_op = HICN_FACE_NONE;
  int prod = 0;


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
	  face_op = HICN_FACE_DELETE;
	}
      else if (face_op == HICN_FACE_DELETE
	       && unformat (line_input, "id %d", &face_id1))
	;
      else if (unformat (line_input, "add"))
	{
	  face_op = HICN_FACE_ADD;
	}
      else if (face_op == HICN_FACE_ADD)
	{
	  if (unformat (line_input, "intfc %U",
			unformat_vnet_sw_interface, vnm, &sw_if))
	    ;
	  else
	    if (unformat
		(line_input, "prod prefix %U/%d", unformat_ip46_address,
		 &prefix.fp_addr, IP46_TYPE_ANY, &prefix.fp_len))
	    {
	      prod = 1;
	    }
	  else if (prod && unformat (line_input, "cs_size %d", &cs_reserved))
	    ;
	  else if (unformat (line_input, "cons"))
	    ;
	  else
	    {
	      return clib_error_return (0, "%s '%U'",
					get_error_string
					(HICN_ERROR_CLI_INVAL),
					format_unformat_error, line_input);
	    }
	}
      else
	{
	  return clib_error_return (0, "%s '%U'",
				    get_error_string (HICN_ERROR_CLI_INVAL),
				    format_unformat_error, line_input);
	}
    }

  if (face_id1 != HICN_FACE_NULL)
    {

      if (!hicn_dpoi_idx_is_valid (face_id1))
	{
	  return clib_error_return (0, "%s, face_id1 %d not valid",
				    get_error_string (ret), face_id1);
	}
    }

  int rv;
  switch (face_op)
    {
    case HICN_FACE_ADD:
      {
	ip46_address_t prod_addr;
	ip4_address_t cons_addr4;
	ip6_address_t cons_addr6;

	if (prod)
	  {
	    prefix.fp_proto =
	      ip46_address_is_ip4 (&prefix.
				   fp_addr) ? FIB_PROTOCOL_IP4 :
	      FIB_PROTOCOL_IP6;
	    rv =
	      hicn_face_prod_add (&prefix, sw_if, &cs_reserved, &prod_addr,
				  &face_id1);
	    if (rv == HICN_ERROR_NONE)
	      {
		u8 *sbuf = NULL;
		sbuf =
		  format (sbuf, "Face id: %d, producer address %U", face_id1,
			  format_ip46_address, &prod_addr,
			  0 /*IP46_ANY_TYPE */ );
		vlib_cli_output (vm, "%s", sbuf);
	      }
	    else
	      {
		return clib_error_return (0, get_error_string (rv));
	      }
	  }
	else
	  {
	    rv =
	      hicn_face_cons_add (&cons_addr4, &cons_addr6, sw_if, &face_id1,
				  &face_id2);
	    if (rv == HICN_ERROR_NONE)
	      {
		u8 *sbuf = NULL;
		sbuf =
		  format (sbuf,
			  "Face id: %d, address v4 %U, face id: %d address v6 %U",
			  face_id1, format_ip4_address, &cons_addr4, face_id2,
			  format_ip6_address, &cons_addr6);
		vlib_cli_output (vm, "%s", sbuf);
	      }
	    else
	      {
		return clib_error_return (0, get_error_string (rv));
	      }
	  }
	break;
      }
    case HICN_FACE_DELETE:
      {
	hicn_face_t *face = hicn_dpoi_get_from_idx (face_id1);

	if (face->flags & HICN_FACE_FLAGS_APPFACE_CONS)
	  rv = hicn_face_cons_del (face_id1);
	else
	  rv = hicn_face_prod_del (face_id1);
	if (rv == HICN_ERROR_NONE)
	  {
	    vlib_cli_output (vm, "Face %d deleted", face_id1);
	  }
	else
	  {
	    return clib_error_return (0, get_error_string (rv));
	  }
	break;
      }
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
VLIB_CLI_COMMAND (hicn_face_app_cli_set_command, static) =
{
  .path = "hicn face app",
  .short_help = "hicn face app {add intfc <sw_if> { prod prefix <hicn_prefix> cs_size <size_in_packets>} {cons} | {del <face_id>}",
  .function = hicn_face_app_cli_set_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
