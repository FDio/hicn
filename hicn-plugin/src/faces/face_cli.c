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
#include "face.h"
#include "../error.h"

static clib_error_t *
hicn_face_cli_show_command_fn (vlib_main_t * vm,
			       unformat_input_t * main_input,
			       vlib_cli_command_t * cmd)
{

  hicn_face_id_t face_id = HICN_FACE_NULL;
  char *face_type_name = NULL;
  int found = ~0;
  int deleted = 0;
  u8 *n = 0;
  u8 *s = 0;
  vlib_counter_t v;

  /* Get a line of input. */
  unformat_input_t _line_input, *line_input = &_line_input;
  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "%u", &face_id))
	    ;
	  else if (unformat (line_input, "type %s", &face_type_name))
	    ;
	  else if (unformat (line_input, "deleted"))
	    deleted = 1;
	  else
	    {
	      return clib_error_return (0, "%s",
					get_error_string
					(HICN_ERROR_CLI_INVAL));
	    }
	}

      if (face_type_name != NULL)
	{
	  int idx = 0;
	  vec_foreach_index (idx, face_type_names_vec)
	  {
	    if (!strcmp (face_type_names_vec[idx], face_type_name))
	      found = idx;
	  }
	  if (found == ~0)
	    return (clib_error_return (0, "Face type unknown"));
	}

    }

  if (face_id != HICN_FACE_NULL)
    {
      if (!hicn_dpoi_idx_is_valid (face_id))
	return clib_error_return (0, "%s",
				  get_error_string
				  (HICN_ERROR_FACE_NOT_FOUND));

      hicn_face_t *face = hicn_dpoi_get_from_idx (face_id);
      vlib_cli_output (vm, "%U\n", format_hicn_face, face_id, 0 /*indent */ );

      u32 indent = 3;

      for (int i = 0; i < HICN_N_COUNTER; i++)
	{
	  vlib_get_combined_counter (&counters
				     [hicn_dpoi_get_index (face) *
				      HICN_N_COUNTER], i, &v);
	  s =
	    format (s, "%U%s", format_white_space, indent,
		    HICN_FACE_CTRX_STRING[i]);

	  if (n)
	    _vec_len (n) = 0;
	  n = format (n, "packets");
	  s =
	    format (s, "%U%-16v%16Ld", format_white_space,
		    30 - strlen (HICN_FACE_CTRX_STRING[i]), n, v.packets);

	  _vec_len (n) = 0;
	  n = format (n, "bytes");
	  s = format (s, "\n%U%-16v%16Ld\n",
		      format_white_space, indent + 30, n, v.bytes);
	}
      vlib_cli_output (vm, "%s\n", s);
    }
  else
    {
      if (found != ~0)
	{
	  hicn_face_t *face;
	  /* *INDENT-OFF* */
          pool_foreach(face, hicn_dpoi_face_pool,
                       {
                         if (!((face->flags & HICN_FACE_FLAGS_DELETED) && !deleted))
                           {
                             if (face->flags)
                               {
                                 vlib_cli_output(vm, "%U\n", format_hicn_face, hicn_dpoi_get_index(face), 0);
                                 u8 * s = 0;
                                 u32 indent = 3;

                                 for (int i = 0; i < HICN_N_COUNTER; i++)
                                   {
                                     vlib_get_combined_counter (&counters[hicn_dpoi_get_index(face) * HICN_N_COUNTER], i, &v);
                                     s = format (s, "%U%s",format_white_space, indent, HICN_FACE_CTRX_STRING[i]);

                                     if (n)
                                       _vec_len (n) = 0;
                                     n = format (n, "packets");
                                     s = format (s, "%U%-16v%16Ld", format_white_space, 30-strlen(HICN_FACE_CTRX_STRING[i]), n, v.packets);

                                     _vec_len (n) = 0;
                                     n = format (n, "bytes");
                                     s = format (s, "\n%U%-16v%16Ld\n",
                                                 format_white_space, indent+30, n, v.bytes);
                                   }
                                 vlib_cli_output (vm, "%s\n", s);
                               }
                           }
                       });
	  /* *INDENT-ON* */
	}
      else
	{
	  hicn_face_t *face;
	  /* *INDENT-OFF* */
          pool_foreach(face, hicn_dpoi_face_pool,
                       {
                         if (!((face->flags & HICN_FACE_FLAGS_DELETED) && !deleted))
                           {
                             vlib_cli_output(vm, "%U\n", format_hicn_face, hicn_dpoi_get_index(face), 0);
                             u32 indent = 3;
                             u8 * s = 0;

                                 for (int i = 0; i < HICN_N_COUNTER; i++)
                                   {
                                     vlib_get_combined_counter (&counters[hicn_dpoi_get_index(face) * HICN_N_COUNTER], i, &v);
                                     s = format (s, "%U%s",format_white_space, indent, HICN_FACE_CTRX_STRING[i]);

                                     if (n)
                                       _vec_len (n) = 0;
                                     n = format (n, "packets");
                                     s = format (s, "%U%-16v%16Ld", format_white_space, 30-strlen(HICN_FACE_CTRX_STRING[i]), n, v.packets);

                                     _vec_len (n) = 0;
                                     n = format (n, "bytes");
                                     s = format (s, "\n%U%-16v%16Ld\n",
                                                 format_white_space, indent+30, n, v.bytes);
                                   }
                                 vlib_cli_output (vm, "%s\n", s);
                           }
                       });
	  /* *INDENT-ON* */
	}
    }

  return 0;
}

/* cli declaration for 'show faces' */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (hicn_face_cli_show_command, static) =
{
  .path = "hicn face show",
  .short_help = "hicn face show [<face_id>]",
  .function = hicn_face_cli_show_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
