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
#include "../hicn.h"
#include "../params.h"
#include "../error.h"
/* #include "../mapme.h" */
/* #include "../mapme_eventmgr.h" */

dpo_id_t *face_dpo_vec;
hicn_face_vft_t *face_vft_vec;
char **face_type_names_vec;

hicn_face_t *hicn_dpoi_face_pool;

dpo_type_t first_type = DPO_FIRST;

vlib_combined_counter_main_t *counters;

dpo_type_t hicn_face_type;

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

/* void */
/* register_face_type (hicn_face_type_t face_type, hicn_face_vft_t * vft, */
/* 		    char *name) */
/* { */
/*   if (first_type == DPO_FIRST) */
/*     first_type = face_type; */

/*   int idx = face_type - first_type; */
/*   ASSERT (idx >= 0); */
/*   vec_validate (face_vft_vec, idx); */
/*   vec_validate (face_type_names_vec, idx); */

/*   /\* Copy the null char as well *\/ */
/*   char *name_str = (char *) malloc ((strlen (name) + 1) * sizeof (char)); */
/*   strcpy (name_str, name); */
/*   face_vft_vec[idx] = *vft; */
/*   face_type_names_vec[idx] = name_str; */
/* } */

mhash_t hicn_face_vec_hashtb;
mhash_t hicn_face_hashtb;

hicn_face_vec_t * hicn_vec_pool;

/* const static char *const hicn_face_nodes[] = */
/* { */
/*  NULL, */
/* }; */

/* const static char *const *const hicn_ip_nodes[DPO_PROTO_NUM] = */
/* { */
/*  [DPO_PROTO_IP4] = hicn_face_nodes, */
/*  [DPO_PROTO_IP6] = hicn_face_nodes */
/* }; */

/* const static dpo_vft_t hicn_face_ip_vft = */
/* { */
/*  .dv_lock = hicn_face_lock, */
/*  .dv_unlock = hicn_face_unlock, */
/*  .dv_format = format_hicn_face_ip, */
/* }; */


// Make this more flexible for future types face
void
hicn_face_module_init (vlib_main_t * vm)
{
  pool_validate (hicn_dpoi_face_pool);
  pool_alloc (hicn_dpoi_face_pool, 1024);
  counters =
    vec_new (vlib_combined_counter_main_t,
	     HICN_PARAM_FACES_MAX * HICN_N_COUNTER);

  mhash_init (&hicn_face_vec_hashtb,
	      sizeof (hicn_face_input_faces_t) /* value */ ,
	      sizeof (hicn_face_key_t) /* key */ );
  mhash_init (&hicn_face_hashtb,
	      sizeof (hicn_face_id_t) /* value */ ,
	      sizeof (hicn_face_key_t) /* key */ );

  pool_alloc(hicn_vec_pool, 100);

  /*
   * How much useful is the following registration?
   * So far it seems that we need it only for setting the dpo_type.
   */
  /* hicn_face_type = */
  /*   dpo_register_new_type (&hicn_face_ip_vft, hicn_ip_nodes); */
}

u8 *
format_hicn_face (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);
  hicn_face_t *face;

  face = hicn_dpoi_get_from_idx (index);

  if (face->flags & HICN_FACE_FLAGS_FACE)
    {
      hicn_face_id_t face_id = hicn_dpoi_get_index (face);
      s = format (s, "%U Face %d: ", format_white_space, indent, face_id);
      s = format (s, "nat address %U locks %u, path_label %u",
		  format_ip46_address, &face->nat_addr, IP46_TYPE_ANY,
                  face->locks, face->pl_id);

      /* if ((face->flags & HICN_FACE_FLAGS_APPFACE_PROD)) */
      /*   s = format (s, " %U", format_hicn_face_prod, face_id, 0); */
      /* else if ((face->shared.flags & HICN_FACE_FLAGS_APPFACE_CONS)) */
      /*   s = format (s, " %U", format_hicn_face_cons, face_id, 0); */

      if ((face->flags & HICN_FACE_FLAGS_DELETED))
	s = format (s, " (deleted)");

      s = format (s, "\n%U%U",
                  format_white_space, indent + 2,
                  format_dpo_id, &face->dpo, indent + 3);
    }
  else
    {
      hicn_face_id_t face_id = hicn_dpoi_get_index (face);
      s = format (s, "%U iFace %d: ", format_white_space, indent, face_id);
      s = format (s, "nat address %U locks %u, path_label %u",
		  format_ip46_address, &face->nat_addr, IP46_TYPE_ANY,
                  face->locks, face->pl_id);

      /* if ((face->shared.flags & HICN_FACE_FLAGS_APPFACE_PROD)) */
      /*   s = format (s, " %U", format_hicn_face_prod, face_id, 0); */
      /* else if ((face->shared.flags & HICN_FACE_FLAGS_APPFACE_CONS)) */
      /*   s = format (s, " %U", format_hicn_face_cons, face_id, 0); */

      if ((face->flags & HICN_FACE_FLAGS_DELETED))
	s = format (s, " (deleted)");
    }

  return s;
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
                   s = format(s, "%U\n", format_hicn_face, hicn_dpoi_get_index(face), indent);
                 });
  /* *INDENT-ON* */

  return s;
}

/* hicn_face_vft_t * */
/* hicn_face_get_vft (hicn_face_type_t face_type) */
/* { */
/*   int idx = face_type - first_type; */
/*   if (idx >= 0) */
/*     return &face_vft_vec[idx]; */
/*   else */
/*     return NULL; */

/* } */

/* FACE IP CODE */

int
hicn_face_del (hicn_face_id_t face_id)
{
  hicn_face_t *face = hicn_dpoi_get_from_idx (face_id);
  hicn_face_key_t key;
  hicn_face_key_t old_key;
  hicn_face_key_t old_key2;

  hicn_face_get_key (&(face->nat_addr), face->sw_if, &(face->dpo),
                     &key);
  hicn_face_input_faces_t *in_faces_vec =
    hicn_face_get_vec (&(face->nat_addr), face->sw_if,
                           &hicn_face_vec_hashtb);
  if (in_faces_vec != NULL)
    {
      hicn_face_vec_t *vec =
        pool_elt_at_index (hicn_vec_pool, in_faces_vec->vec_id);
      u32 index_face = vec_search (*vec, face_id);
      vec_del1 (*vec, index_face);

      if (vec_len (*vec) == 0)
        {
          pool_put_index (hicn_vec_pool, in_faces_vec->vec_id);
          mhash_unset (&hicn_face_vec_hashtb, &key,
                       (uword *) & old_key);
          vec_free (*vec);
        }
      else
        {
          /* Check if the face we are deleting is the preferred one. */
          /* If so, repleace with another. */
          if (in_faces_vec->face_id == face_id)
            {
              in_faces_vec->face_id = (*vec)[0];
            }
        }

      mhash_unset (&hicn_face_hashtb, &key,
                   (uword *) & old_key2);
    }

  int ret = HICN_ERROR_NONE;

  if (hicn_dpoi_idx_is_valid (face_id))
    {
      hicn_face_t *face = hicn_dpoi_get_from_idx (face_id);
      face->locks--;
      if (face->locks == 0)
	pool_put_index (hicn_dpoi_face_pool, face_id);
      else
	face->flags |= HICN_FACE_FLAGS_DELETED;
    }
  else
    ret = HICN_ERROR_FACE_NOT_FOUND;


  return ret;
}

static void
hicn_iface_to_face(hicn_face_t *face, const dpo_id_t * dpo)
{
  face->dpo = *dpo;

  face->flags &=  ~HICN_FACE_FLAGS_IFACE;
  face->flags |=  HICN_FACE_FLAGS_FACE;
}

/*
 * Utility that adds a new face cache entry. For the moment we assume that
 * the ip_adjacency has already been set up.
 */
int
hicn_face_add (const dpo_id_t * dpo_nh, ip46_address_t * nat_address,
               int sw_if, hicn_face_id_t * pfaceid, u8 is_app_prod)
{
  //  dpo_proto_t dpo_proto;

  hicn_face_flags_t flags = (hicn_face_flags_t) 0;
  flags |= HICN_FACE_FLAGS_FACE;

  hicn_face_t *face;

  face =
    hicn_face_get_with_dpo (nat_address, sw_if, dpo_nh,
                            &hicn_face_hashtb);

  if (face != NULL)
    return HICN_ERROR_FACE_ALREADY_CREATED;

  face =
    hicn_face_get (nat_address, sw_if,
                   &hicn_face_hashtb);

  dpo_id_t temp_dpo = DPO_INVALID;
  hicn_face_key_t key;
  hicn_face_get_key (nat_address, sw_if, &temp_dpo, &key);

  if (face == NULL)
    {

      hicn_iface_add (nat_address, sw_if, pfaceid, dpo_nh->dpoi_proto);
      face = hicn_dpoi_get_from_idx (*pfaceid);

      mhash_set_mem (&hicn_face_hashtb, &key, (uword *) pfaceid,
                     0);

      hicn_face_get_key (nat_address, sw_if, &temp_dpo, &key);
      mhash_set_mem (&hicn_face_hashtb, &key, (uword *) pfaceid,
                     0);
    }
  else
    {
      /* *We found an iface and we convert it to a face */
      *pfaceid = hicn_dpoi_get_index (face);
      mhash_set_mem (&hicn_face_hashtb, &key, (uword *) pfaceid,
                     0);
    }

  hicn_iface_to_face(face, dpo_nh);


  hicn_face_input_faces_t *in_faces =
    hicn_face_get_vec (nat_address, sw_if,
                       &hicn_face_vec_hashtb);

  if (in_faces == NULL)
    {
      hicn_face_input_faces_t in_faces_temp;
      hicn_face_vec_t *vec;
      pool_get (hicn_vec_pool, vec);
      *vec = vec_new (hicn_face_vec_t, 0);
      u32 index = vec - hicn_vec_pool;
      in_faces_temp.vec_id = index;
      vec_add1 (*vec, *pfaceid);


      //      dpo_proto = DPO_PROTO_IP4;

      in_faces_temp.face_id = *pfaceid;

      hicn_face_get_key (nat_address, sw_if, &temp_dpo, &key);

      mhash_set_mem (&hicn_face_vec_hashtb, &key,
                     (uword *) & in_faces_temp, 0);
    }
  else
    {
      hicn_face_vec_t *vec =
        pool_elt_at_index (hicn_vec_pool, in_faces->vec_id);

      /* */
      if (vec_search (*vec, *pfaceid) != ~0)
        return HICN_ERROR_FACE_ALREADY_CREATED;

      vec_add1 (*vec, *pfaceid);

      hicn_iface_to_face(face, dpo_nh);

      //      dpo_proto = DPO_PROTO_IP4;

      hicn_face_get_key (nat_address, sw_if, &temp_dpo, &key);

      mhash_set_mem (&hicn_face_vec_hashtb, &key, (uword *) in_faces,
                     0);

      /* If the face is an application producer face, we set it as the preferred incoming face. */
      /* This is required to handle the CS separation, and the push api in a lightway */
      if (is_app_prod)
        {
          in_faces->face_id = *pfaceid;
        }
    }

  /* retx_t *retx = vlib_process_signal_event_data (vlib_get_main (), */
  /*       					 hicn_mapme_eventmgr_process_node.index, */
  /*       					 HICN_MAPME_EVENT_FACE_ADD, 1, */
  /*       					 sizeof (retx_t)); */

  /* /\* *INDENT-OFF* *\/ */
  /* *retx = (retx_t) */
  /* { */
  /*   .prefix = 0, */
  /*   .dpo = (dpo_id_t) */
  /*   { */
  /*     .dpoi_type = 0, */
  /*     .dpoi_proto = dpo_proto, */
  /*     .dpoi_next_node = 0, */
  /*     .dpoi_index = *pfaceid, */
  /*   } */
  /* }; */
  /* /\* *INDENT-ON* *\/ */

  return HICN_ERROR_NONE;
}

/* void */
/* hicn_face_get_dpo (hicn_face_t * face, dpo_id_t * dpo) */
/* { */

/*   hicn_face_ip_t *face_ip = (hicn_face_ip_t *) face->data; */
/*   return hicn_dpo_ip_create_from_face (face, dpo, */
/* 				       ip46_address_is_ip4 */
/* 				       (&face_ip->remote_addr) ? */
/* 				       strategy_face_ip4_vlib_edge : */
/* 				       strategy_face_ip6_vlib_edge); */
/* } */



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
