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

#include "face.h"
#include "ip/face_ip.h"
#include "ip/face_ip_node.h"
#include "ip/iface_ip_node.h"
#include "ip/dpo_ip.h"
#include "udp/face_udp.h"
#include "udp/face_udp_node.h"
#include "udp/iface_udp_node.h"
#include "udp/dpo_udp.h"

dpo_id_t *face_dpo_vec;
hicn_face_vft_t *face_vft_vec;
char **face_type_names_vec;

hicn_face_t *hicn_dpoi_face_pool;

dpo_type_t first_type = DPO_FIRST;

vlib_combined_counter_main_t *counters;

const char *HICN_FACE_CTRX_STRING[] = {
#define _(a,b,c) c,
  foreach_hicn_face_counter
#undef _
};

u8 *
face_show (u8 * s, int face_id, u32 indent)
{
  s = format (s, "%U Faces:\n", format_white_space, indent);
  indent += 4;
  int i;
  vec_foreach_index (i, face_dpo_vec)
  {
    s =
      format (s, "%U", face_vft_vec[i].format_face,
	      face_dpo_vec[face_id].dpoi_index, indent);
  }

  return (s);

}

void
register_face_type (hicn_face_type_t face_type, hicn_face_vft_t * vft,
		    char *name)
{
  if (first_type == DPO_FIRST)
    first_type = face_type;

  int idx = face_type - first_type;
  ASSERT (idx >= 0);
  vec_validate (face_vft_vec, idx);
  vec_validate (face_type_names_vec, idx);

  /* Copy the null char as well */
  char *name_str = (char *) malloc ((strlen (name) + 1) * sizeof (char));
  strcpy (name_str, name);
  face_vft_vec[idx] = *vft;
  face_type_names_vec[idx] = name_str;
}

// Make this more flexible for future types face
void
hicn_face_module_init (vlib_main_t * vm)
{
  pool_validate (hicn_dpoi_face_pool);
  pool_alloc (hicn_dpoi_face_pool, 1024);
  hicn_face_ip_init (vm);
  hicn_iface_ip_init (vm);
  hicn_face_udp_init (vm);
  hicn_iface_udp_init (vm);
  counters =
    vec_new (vlib_combined_counter_main_t,
	     HICN_PARAM_FACES_MAX * HICN_N_COUNTER);
}

u8 *
format_hicn_face_all (u8 * s, int n, ...)
{
  va_list ap;
  va_start (ap, n);
  u32 indent = va_arg (ap, u32);

  s = format (s, "%U Faces:\n", format_white_space, indent);

  hicn_face_t *face;

  /* *INDENT-OFF* */
  pool_foreach ( face, hicn_dpoi_face_pool,
                 {
                   hicn_face_vft_t * vft = hicn_face_get_vft(face->shared.face_type);
                   hicn_face_id_t face_id = hicn_dpoi_get_index(face);
                   s = format(s, "%U\n", vft->format_face, face_id, indent);
                 });
  /* *INDENT-ON* */

  return s;
}

hicn_face_vft_t *
hicn_face_get_vft (hicn_face_type_t face_type)
{
  int idx = face_type - first_type;
  if (idx >= 0)
    return &face_vft_vec[idx];
  else
    return NULL;

}

int
hicn_face_del (hicn_face_id_t face_id)
{
  int ret = HICN_ERROR_NONE;

  if (hicn_dpoi_idx_is_valid (face_id))
    {
      hicn_face_t *face = hicn_dpoi_get_from_idx (face_id);
      face->shared.locks--;
      if (face->shared.locks == 0)
	pool_put_index (hicn_dpoi_face_pool, face_id);
      else
	face->shared.flags |= HICN_FACE_FLAGS_DELETED;
    }
  else
    ret = HICN_ERROR_FACE_NOT_FOUND;

  return ret;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
