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

#ifndef __HICN_DPO_H__
#define __HICN_DPO_H__

#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/adj/adj_midchain.h>

#include "face.h"
#include "../error.h"

/**
 * @brief Initialize the internal structures of the dpo ip face module.
 */
//void hicn_dpo_ip_module_init (void);


/**
 * @brief Retrieve a vector of faces from the ip4 local address and returns its index.
 *
 * @param vec: Result of the lookup. If no face exists for the local address vec = NULL
 * @param hicnb_flags: Flags that indicate whether the face is an application
 * face or not
 * @param local_addr: Ip v4 nat address of the face
 * @param sw_if: software interface id of the face
 *
 * @result HICN_ERROR_FACE_NOT_FOUND if the face does not exist, otherwise HICN_ERROR_NONE.
 */
always_inline int
hicn_dpo_face_ip4_lock (hicn_face_id_t * face_id,
                        u32 * in_faces_vec_id,
                        u8 * hicnb_flags,
                        const ip4_address_t * nat_addr)
{
  ip46_address_t ip_address = {0};
  ip46_address_set_ip4(&ip_address, nat_addr);
  hicn_face_input_faces_t *in_faces_vec =
    hicn_face_get_vec (&ip_address, &hicn_face_vec_hashtb);

  if (PREDICT_FALSE (in_faces_vec == NULL))
    return HICN_ERROR_FACE_NOT_FOUND;

  *in_faces_vec_id = in_faces_vec->vec_id;
  hicn_face_t *face = hicn_dpoi_get_from_idx (in_faces_vec->face_id);

  *hicnb_flags = HICN_BUFFER_FLAGS_DEFAULT;
  *hicnb_flags |=
    (face->flags & HICN_FACE_FLAGS_APPFACE_PROD) >>
    HICN_FACE_FLAGS_APPFACE_PROD_BIT;

  *face_id = in_faces_vec->face_id;

  return HICN_ERROR_NONE;
}

/**
 * @brief Retrieve a face from the ip6 local address and returns its dpo. This
 * method adds a lock on the face state.
 *
 * @param dpo: Result of the lookup. If the face doesn't exist dpo = NULL
 * @param hicnb_flags: Flags that indicate whether the face is an application
 * face or not
 * @param nat_addr: Ip v6 nat address of the face
 * @param sw_if: software interface id of the face
 *
 * @result HICN_ERROR_FACE_NOT_FOUND if the face does not exist, otherwise HICN_ERROR_NONE.
 */
always_inline int
hicn_dpo_face_ip6_lock (hicn_face_id_t * face_id,
                        u32 * in_faces_vec_id,
                        u8 * hicnb_flags,
                        const ip6_address_t * nat_addr)
{
  hicn_face_input_faces_t *in_faces_vec =
    hicn_face_get_vec ((ip46_address_t *)nat_addr, &hicn_face_vec_hashtb);

  if (PREDICT_FALSE (in_faces_vec == NULL))
    return HICN_ERROR_FACE_NOT_FOUND;

  *in_faces_vec_id = in_faces_vec->vec_id;
  hicn_face_t *face = hicn_dpoi_get_from_idx (in_faces_vec->face_id);

  *hicnb_flags = HICN_BUFFER_FLAGS_DEFAULT;
  *hicnb_flags |=
    (face->flags & HICN_FACE_FLAGS_APPFACE_PROD) >>
    HICN_FACE_FLAGS_APPFACE_PROD_BIT;

  *face_id = in_faces_vec->face_id;

  return HICN_ERROR_NONE;
}

/**
 * @brief Call back to get the adj of the tunnel
 */
static adj_walk_rc_t
hicn4_iface_adj_walk_cb (adj_index_t ai,
                        void *ctx)
{

  hicn_face_t *face = (hicn_face_t *)ctx;

  dpo_set(&face->dpo, DPO_ADJACENCY_MIDCHAIN, DPO_PROTO_IP4, ai);
  adj_nbr_midchain_stack(ai, &face->dpo);

  return (ADJ_WALK_RC_CONTINUE);
}

/**
 * @brief Retrieve, or create if it doesn't exist, a face from the ip6 local
 * address and returns its dpo. This method adds a lock on the face state.
 *
 * @param dpo: Result of the lookup
 * @param hicnb_flags: Flags that indicate whether the face is an application
 * face or not
 * @param nat_addr: Ip v4 remote address of the face
 * @param sw_if: software interface id of the face
 * @param node_index: vlib edge index to use in the packet processing
 */
always_inline void
hicn_dpo_iface_ip4_add_and_lock (hicn_face_id_t * index,
                                 u8 * hicnb_flags,
                                 const ip4_address_t * nat_addr,
                                 u32 sw_if, u32 adj_index, u32 node_index)
{
  /*All (complete) faces are indexed by remote addess as well */

  ip46_address_t ip_address = {0};
  ip46_address_set_ip4(&ip_address, nat_addr);

  /* if the face exists, it adds a lock */
  hicn_face_t *face =
    hicn_face_get (&ip_address, sw_if, &hicn_face_hashtb);

  if (face == NULL)
    {
      hicn_face_id_t idx;
      hicn_iface_add (&ip_address, sw_if, &idx, DPO_PROTO_IP4);

      face = hicn_dpoi_get_from_idx(idx);

      face->dpo.dpoi_type = DPO_FIRST;
      face->dpo.dpoi_proto = DPO_PROTO_IP4;
      face->dpo.dpoi_index = adj_index;
      face->dpo.dpoi_next_node = node_index;

      /* if (nat_addr->as_u32 == 0) */
      /*   { */
          adj_nbr_walk(face->sw_if,
                       FIB_PROTOCOL_IP4,
                       hicn4_iface_adj_walk_cb,
                       face);
        /* } */

      *hicnb_flags = HICN_BUFFER_FLAGS_DEFAULT;

      *index = idx;
      return;
    }
  else
    {
      /* unlock the face. We don't take a lock on each interest we receive */
      hicn_face_id_t face_id = hicn_dpoi_get_index(face);
      hicn_face_unlock_with_id(face_id);
    }

  /* Code replicated on purpose */
  *hicnb_flags = HICN_BUFFER_FLAGS_DEFAULT;
  *hicnb_flags |=
    (face->flags & HICN_FACE_FLAGS_APPFACE_PROD) >>
    HICN_FACE_FLAGS_APPFACE_PROD_BIT;

  *index = hicn_dpoi_get_index (face);
}

/**
 * @brief Call back to get the adj of the tunnel
 */
static adj_walk_rc_t
hicn6_iface_adj_walk_cb (adj_index_t ai,
                         void *ctx)
{

  hicn_face_t *face = (hicn_face_t *)ctx;

  ip_adjacency_t *adj = adj_get(ai);
  if ((adj->lookup_next_index == IP_LOOKUP_NEXT_MIDCHAIN) ||
      (adj->lookup_next_index == IP_LOOKUP_NEXT_MCAST_MIDCHAIN))
    {
      dpo_set(&face->dpo, DPO_ADJACENCY_MIDCHAIN, adj->ia_nh_proto, ai);
      adj_nbr_midchain_stack(ai, &face->dpo);
    }

  return (ADJ_WALK_RC_CONTINUE);
}


/**
 * @brief Retrieve, or create if it doesn't exist, a face from the ip6 local
 * address and returns its dpo. This method adds a lock on the face state.
 *
 * @param dpo: Result of the lookup
 * @param hicnb_flags: Flags that indicate whether the face is an application
 * face or not
 * @param nat_addr: Ip v6 remote address of the face
 * @param sw_if: software interface id of the face
 * @param node_index: vlib edge index to use in the packet processing
 */
always_inline void
hicn_dpo_iface_ip6_add_and_lock (hicn_face_id_t * index,
                                 u8 * hicnb_flags,
                                 const ip6_address_t * nat_addr,
                                 u32 sw_if, u32 adj_index, u32 node_index)
{
  /*All (complete) faces are indexed by remote addess as well */
  /* if the face exists, it adds a lock */
  hicn_face_t *face =
    hicn_face_get ((ip46_address_t *)nat_addr, sw_if, &hicn_face_hashtb);

  if (face == NULL)
    {
      hicn_face_id_t idx;
      hicn_iface_add ((ip46_address_t *) nat_addr, sw_if, &idx, DPO_PROTO_IP6);

      face = hicn_dpoi_get_from_idx(idx);

      face->dpo.dpoi_type = DPO_FIRST;
      face->dpo.dpoi_proto = DPO_PROTO_IP6;
      face->dpo.dpoi_index = adj_index;
      face->dpo.dpoi_next_node = node_index;

      //if (ip46_address_is_zero((ip46_address_t *)nat_addr))
      //  {
      adj_nbr_walk(face->sw_if,
                   FIB_PROTOCOL_IP6,
                   hicn6_iface_adj_walk_cb,
                   face);
          //  }

      *hicnb_flags = HICN_BUFFER_FLAGS_DEFAULT;

      *index = idx;

      return;
    }
  else
    {
      /* unlock the face. We don't take a lock on each interest we receive */
      hicn_face_id_t face_id = hicn_dpoi_get_index(face);
      hicn_face_unlock_with_id(face_id);
    }

  /* Code replicated on purpose */
  *hicnb_flags = HICN_BUFFER_FLAGS_DEFAULT;
  *hicnb_flags |=
    (face->flags & HICN_FACE_FLAGS_APPFACE_PROD) >>
    HICN_FACE_FLAGS_APPFACE_PROD_BIT;

  *index = hicn_dpoi_get_index (face);
}


/* /\** */
/*  * @brief Create an ip face and its corresponding dpo. Meant to be used for the */
/*  * control plane. */
/*  * */
/*  * @param dpo: Data plane object that point to the face created. */
/*  * @param local_addr: Ip v4 local address of the face */
/*  * @param remote_addr: Ip v4 remote address of the face */
/*  * @param sw_if: software interface id of the face */
/*  * @param adj: Ip adjacency corresponding to the remote address in the face */
/*  * @param node_index: vlib edge index to use in the packet processing */
/*  * @param flags: Flags of the face */
/*  * @param face_id: Identifier for the face (dpoi_index) */
/*  * @return HICN_ERROR_FACE_ALREADY_CREATED if the face exists, otherwise HICN_ERROR_NONE */
/*  *\/ */
/* int hicn_dpo_ip4_create (dpo_id_t * dpo, */
/* 			 const ip4_address_t * local_addr, */
/* 			 const ip4_address_t * remote_addr, */
/* 			 u32 sw_if, */
/* 			 adj_index_t adj, */
/* 			 u32 node_index, */
/* 			 hicn_face_flags_t flags, hicn_face_id_t * face_id); */

/* /\** */
/*  * @brief Create an ip face and its corresponding dpo. Meant to be used for the */
/*  * control plane. */
/*  * */
/*  * @param dpo: Data plane object that point to the face created. */
/*  * @param local_addr: Ip v6 local address of the face */
/*  * @param remote_addr: Ip v6 remote address of the face */
/*  * @param sw_if: software interface id of the face */
/*  * @param adj: Ip adjacency corresponding to the remote address in the face */
/*  * @param node_index: vlib edge index to use in the packet processing */
/*  * @param flags: Flags of the face */
/*  * @param face_id: Identifier for the face (dpoi_index) */
/*  * @return HICN_ERROR_FACE_ALREADY_CREATED if the face exists, otherwise HICN_ERROR_NONE */
/*  *\/ */
/* int hicn_dpo_ip6_create (dpo_id_t * dpo, */
/* 			 const ip6_address_t * local_addr, */
/* 			 const ip6_address_t * remote_addr, */
/* 			 u32 sw_if, */
/* 			 adj_index_t adj, */
/* 			 u32 node_index, */
/* 			 hicn_face_flags_t flags, hicn_face_id_t * face_id); */

#endif // __HICN_DPO_IP_H__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
