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

#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_track.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip.h>
#include <vnet/dpo/dpo.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/udp/udp.h>
#include <vnet/udp/udp_encap.h>
#include <vlib/global_funcs.h>

#include "strategy_dpo_ctx.h"
#include "strategy_dpo_manager.h"
#include "strategy.h"
#include "faces/face.h"
#include "error.h"
#include "strategies/dpo_mw.h"
#include "infra.h"
#include "udp_tunnels/udp_tunnel.h"

#define FIB_SOURCE_HICN 0x04	//Right after the FIB_SOURCE_INTERFACE priority

fib_source_t hicn_fib_src;

fib_node_type_t hicn_fib_node_type;

ip4_address_t localhost4 = {0};
ip6_address_t localhost6 = {0};

int
hicn_route_get_dpo (const fib_prefix_t * prefix,
		    const dpo_id_t ** hicn_dpo, u32 * fib_index)
{
  //fib_prefix_t fib_pfx;
  const dpo_id_t *load_balance_dpo_id;
  const dpo_id_t *former_dpo_id;
  int found = 0, ret = HICN_ERROR_ROUTE_NOT_FOUND;
  fib_node_index_t fib_entry_index;

  /* Check if the route already exist in the fib */
  /*
   * ASSUMPTION: we use table 0 which is the default table and it is
   * already existing and locked
   */
  *fib_index = fib_table_find_or_create_and_lock (prefix->fp_proto,
						  HICN_FIB_TABLE,
						  hicn_fib_src);
  fib_entry_index = fib_table_lookup_exact_match (*fib_index, prefix);

  if (fib_entry_index != FIB_NODE_INDEX_INVALID)
    {
      /* Route already existing. We need to update the dpo. */
      load_balance_dpo_id =
	fib_entry_contribute_ip_forwarding (fib_entry_index);

      /* The dpo is not a load balance dpo as expected */
      if (load_balance_dpo_id->dpoi_type != DPO_LOAD_BALANCE)
	ret = HICN_ERROR_ROUTE_NO_LD;
      else
	{
	  /* former_dpo_id is a load_balance dpo */
	  load_balance_t *lb =
	    load_balance_get (load_balance_dpo_id->dpoi_index);

	  /* FIB entry exists but there is no hicn dpo. */
	  ret = HICN_ERROR_ROUTE_DPO_NO_HICN;
	  for (int i = 0; i < lb->lb_n_buckets && !found; i++)
	    {
	      former_dpo_id = load_balance_get_bucket_i (lb, i);

	      if (dpo_is_hicn (former_dpo_id))
		{
		  *hicn_dpo = former_dpo_id;
		  ret = HICN_ERROR_NONE;
		  found = 1;
		}
	    }
	}
    }
  /*
   * Remove the lock from the table. We keep one lock per route, not
   * per dpo
   */
  fib_table_unlock (*fib_index, prefix->fp_proto, hicn_fib_src);

  return ret;
}

int
hicn_route_set_strategy (fib_prefix_t * prefix, u8 strategy_id)
{
  const dpo_id_t *hicn_dpo_id;
  dpo_id_t new_dpo_id = DPO_INVALID;
  int ret;
  hicn_dpo_ctx_t *old_hicn_dpo_ctx;
  const hicn_dpo_vft_t *new_dpo_vft;
  index_t new_hicn_dpo_idx;
  u32 fib_index;

  ret = hicn_route_get_dpo (prefix, &hicn_dpo_id, &fib_index);

  if (ret == HICN_ERROR_NONE)
    {
      old_hicn_dpo_ctx = hicn_strategy_dpo_ctx_get (hicn_dpo_id->dpoi_index);

      new_dpo_vft = hicn_dpo_get_vft_from_id (strategy_id);

      if (new_dpo_vft == NULL || old_hicn_dpo_ctx == NULL)
	return HICN_ERROR_STRATEGY_NOT_FOUND;

      /* Create a new dpo for the new strategy */
      new_dpo_vft->hicn_dpo_create (hicn_dpo_id->dpoi_proto,
				    old_hicn_dpo_ctx->next_hops,
				    old_hicn_dpo_ctx->entry_count,
				    &new_hicn_dpo_idx);

      /* the value we got when we registered */
      dpo_set (&new_dpo_id,
	       new_dpo_vft->hicn_dpo_get_type (),
	       (ip46_address_is_ip4 (&prefix->fp_addr) ? DPO_PROTO_IP4 :
		DPO_PROTO_IP6), new_hicn_dpo_idx);

      /* Here is where we create the "via" like route */
      /*
       * For the moment we use the global one the prefix you want
       * to match Neale suggested -- FIB_SOURCE_HICN the client
       * that is adding them -- no easy explanation at this time…
       */
      fib_node_index_t new_fib_node_index =
	fib_table_entry_special_dpo_update (fib_index,
					    prefix,
					    hicn_fib_src,
					    FIB_ENTRY_FLAG_EXCLUSIVE,
					    &new_dpo_id);

      dpo_unlock (&new_dpo_id);
      ret =
	(new_fib_node_index !=
	 FIB_NODE_INDEX_INVALID) ? HICN_ERROR_NONE :
	HICN_ERROR_ROUTE_NOT_UPDATED;
    }
  //Remember to remove the lock from the table when removing the entry
  return ret;

}

int
ip_nh_add_helper (fib_protocol_t fib_proto, const fib_prefix_t * rpfx, ip46_address_t * nh, u32 sw_if)
{
  fib_route_path_t *rpaths = NULL, rpath;

  u32 fib_index = fib_table_find(fib_proto, 0);

  clib_memset(&rpath, 0, sizeof(rpath));
  rpath.frp_weight = 1;
  rpath.frp_sw_if_index = sw_if;
  rpath.frp_addr = *nh;
  rpath.frp_proto = ip46_address_is_ip4(nh) ? DPO_PROTO_IP4 : DPO_PROTO_IP6;

  vec_add1(rpaths, rpath);

  fib_table_entry_path_add2 (fib_index,
                             rpfx,
                             FIB_SOURCE_CLI,
                             FIB_ENTRY_FLAG_NONE, rpaths);
  return 0;
}

int
ip_nh_del_helper (fib_protocol_t fib_proto, const fib_prefix_t * rpfx, ip46_address_t * nh, u32 sw_if)
{
  fib_route_path_t *rpaths = NULL, rpath;

  u32 fib_index = fib_table_find(fib_proto, 0);

  clib_memset(&rpath, 0, sizeof(rpath));
  rpath.frp_weight = 1;
  rpath.frp_sw_if_index = sw_if;
  rpath.frp_addr = *nh;
  rpath.frp_proto = ip46_address_is_ip4(nh) ? DPO_PROTO_IP4 : DPO_PROTO_IP6;

  vec_add1(rpaths, rpath);

  fib_table_entry_path_remove2 (fib_index,
                                rpfx,
                                FIB_SOURCE_CLI,
                                rpaths);
  return 0;
}


static ip46_address_t * get_address(ip46_address_t * nh, u32 sw_if, fib_protocol_t proto)
{
  ip46_address_t * local_address = calloc(1, sizeof(ip46_address_t));

  if (proto == FIB_PROTOCOL_IP4)
    {
      ip_interface_address_t *interface_address;
      ip4_address_t *addr =
        ip4_interface_address_matching_destination (&ip4_main,
                                                    &nh->ip4,
                                                    sw_if,
                                                    &interface_address);

      if (addr == NULL)
        addr = ip4_interface_first_address (&ip4_main,
                                            sw_if,
                                            &interface_address);
      if (addr != NULL)
        ip46_address_set_ip4 (local_address, addr);
    }
  else if (proto == FIB_PROTOCOL_IP6)
    {
      ip_interface_address_t *interface_address;
      ip6_interface_address_matching_destination (&ip6_main,
                                                  &nh->ip6,
                                                  sw_if,
                                                  &interface_address);

      ip6_address_t *addr = NULL;
      if (interface_address != NULL)
        addr =
          (ip6_address_t *)
          ip_interface_address_get_address (&ip6_main.lookup_main,
                                            interface_address);

      if (addr == NULL)
        addr = ip6_interface_first_address (&ip6_main, sw_if);

      if (addr != NULL)
        ip46_address_set_ip6 (local_address, addr);
    }

  return local_address;
}

static void
sync_hicn_fib_entry(hicn_dpo_ctx_t *fib_entry)
{
  const dpo_id_t * dpo_loadbalance = fib_entry_contribute_ip_forwarding (fib_entry->fib_entry_index);
  const load_balance_t *lb0 = load_balance_get(dpo_loadbalance->dpoi_index);
  index_t hicn_fib_entry_index = hicn_strategy_dpo_ctx_get_index(fib_entry);
  hicn_face_id_t * vec_faces = 0;

  dpo_id_t temp = DPO_INVALID;
  const dpo_id_t *former_dpo = &temp;
  int index = 0;
  for (int j = 0; j < lb0->lb_n_buckets; j++) {
    const dpo_id_t * dpo = load_balance_get_bucket_i(lb0,j);

    int dpo_comparison = dpo_cmp(former_dpo, dpo);
    former_dpo = dpo;
    /*
     * Loadbalancing in ip replicate the dpo in multiple buckets
     * in order to honor the assigned weights.
     */
    if (dpo_comparison == 0)
        continue;

    u32 sw_if = ~0;
    ip46_address_t * nh = NULL;
    hicn_face_id_t face_id = HICN_FACE_NULL;

    if (dpo_is_adj(dpo))
      {
        ip_adjacency_t * adj = adj_get (dpo->dpoi_index);
        sw_if = adj->rewrite_header.sw_if_index;
        nh = get_address (&(adj->sub_type.nbr.next_hop), sw_if, fib_entry->proto);
      }
    else if (dpo->dpoi_type == dpo_type_udp_ip4 || dpo->dpoi_type == dpo_type_udp_ip6)
      {
        udp_encap_t * udp_encap = udp_encap_get(dpo->dpoi_index);
        switch (dpo->dpoi_proto)
          {
          case FIB_PROTOCOL_IP6:
            nh = calloc (1, sizeof(ip46_address_t));
            ip46_address_set_ip6(nh, &(udp_encap->ue_hdrs.ip6.ue_ip6.src_address));
            break;
          case FIB_PROTOCOL_IP4:
            nh = calloc (1, sizeof(ip46_address_t));
            ip46_address_set_ip4(nh, &(udp_encap->ue_hdrs.ip4.ue_ip4.src_address));
            break;
          default:
            nh = calloc (1, sizeof(ip46_address_t));
          }
        udp_tunnel_add_existing (dpo->dpoi_index, dpo->dpoi_proto);
      }
    else //if (dpo_is_drop(dpo))
      {
        sw_if = dpo_get_urpf(dpo);
        nh = calloc (1, sizeof(ip46_address_t));
      }

    /* Careful, this adds a lock on the face if it exists */
    hicn_face_add(dpo, nh, sw_if, &face_id, 0);

    vec_validate(vec_faces, index);
    vec_faces[index] = face_id;
    index++;
  }

  const hicn_dpo_vft_t * strategy_vft = hicn_dpo_get_vft(fib_entry->dpo_type);
  int i = 0;
  while (i < fib_entry->entry_count)
    {
      u32 idx_nh = vec_search(vec_faces, fib_entry->next_hops[i]);
      if (idx_nh == ~0)
        {
          strategy_vft->hicn_dpo_del_nh(fib_entry->next_hops[i], hicn_fib_entry_index);
        }
      else
        {
          // hicn_face_t * face = hicn_dpoi_get_from_idx(fib_entry->next_hops[i]);

         /* if (fib_entry->proto == FIB_PROTOCOL_IP4 && face->sw_if != ~0) */
         /*   vnet_feature_enable_disable ("ip4-local", "hicn-data-input-ip4", */
         /*                                face->sw_if, 1, 0, 0); */
         /* else if (fib_entry->proto == FIB_PROTOCOL_IP6 && face->sw_if != ~0) */
         /*   vnet_feature_enable_disable ("ip6-local", "hicn-data-input-ip6", */
         /*                                face->sw_if, 1, 0, 0); */

         vec_del1(vec_faces, idx_nh);

         /* Remove the lock added by hicn_face_add */
         hicn_face_unlock_with_id (fib_entry->next_hops[i]);
         i++;
        }
    }

  hicn_face_id_t *face_id;
  vec_foreach(face_id, vec_faces)
    {
      strategy_vft->hicn_dpo_add_update_nh(*face_id, hicn_fib_entry_index);

      //hicn_face_t * face = hicn_dpoi_get_from_idx(*face_id);

      /* if (fib_entry->proto == FIB_PROTOCOL_IP4 && face->sw_if != ~0) */
      /*   vnet_feature_enable_disable ("ip4-local", "hicn-data-input-ip4", */
      /*                                face->sw_if, 1, 0, 0); */
      /* else if (fib_entry->proto == FIB_PROTOCOL_IP6 && face->sw_if != ~0) */
      /*   vnet_feature_enable_disable ("ip6-local", "hicn-data-input-ip6", */
      /*                                face->sw_if, 1, 0, 0); */

      /* Remove the lock added by hicn_face_add */
      hicn_face_unlock_with_id (*face_id);

    }
  vec_free(vec_faces);
}

static void
enable_disable_data_receiving (fib_protocol_t proto, u32 sw_if, u8 is_enable)
{
  if (proto == FIB_PROTOCOL_IP4 && sw_if != ~0)
    vnet_feature_enable_disable ("ip4-local", "hicn-data-input-ip4",
                                 sw_if, is_enable, 0, 0);
  else if (proto == FIB_PROTOCOL_IP6 && sw_if != ~0)
    vnet_feature_enable_disable ("ip6-local", "hicn-data-input-ip6",
                                 sw_if, is_enable, 0, 0);

}

walk_rc_t enable_data_receiving_new_fib_entry (vnet_main_t * vnm,
                                 vnet_sw_interface_t * si,
                                 void *ctx)
{
  fib_protocol_t *proto = (fib_protocol_t *) ctx;
  enable_disable_data_receiving(*proto, si->sw_if_index, 1);

  return (WALK_CONTINUE);
}

walk_rc_t disable_data_receiving_rm_fib_entry (vnet_main_t * vnm,
                                  vnet_sw_interface_t * si,
                                  void *ctx)
{
  fib_protocol_t *proto = (fib_protocol_t *) ctx;
  enable_disable_data_receiving(*proto, si->sw_if_index, 0);

  return (WALK_CONTINUE);
    }

int
hicn_route_enable (fib_prefix_t *prefix) {

  int ret = HICN_ERROR_NONE;
  fib_node_index_t fib_entry_index;

  /* Check if the route already exist in the fib */
  /*
   * ASSUMPTION: we use table 0 which is the default table and it is
   * already existing and locked
   */
  u32 fib_index = fib_table_find(prefix->fp_proto, 0);

  fib_entry_index = fib_table_lookup_exact_match (fib_index, prefix);

  if (fib_entry_index == FIB_NODE_INDEX_INVALID)
    {
      fib_entry_index = fib_table_lookup (fib_index, prefix);

      fib_route_path_t * paths = fib_entry_encode(fib_entry_index);

      fib_table_entry_path_add2(fib_index, prefix, FIB_SOURCE_CLI, FIB_ENTRY_FLAG_NONE, paths);
    }

  /* Check if the prefix is already enabled */
  u32 fib_hicn_index = fib_table_find(prefix->fp_proto, HICN_FIB_TABLE);

  fib_node_index_t fib_hicn_entry_index = fib_table_lookup_exact_match (fib_hicn_index, prefix);

  if (fib_hicn_entry_index == FIB_NODE_INDEX_INVALID)
    {
      dpo_id_t dpo = DPO_INVALID;
      index_t dpo_idx;
      default_dpo.hicn_dpo_create (prefix->fp_proto, 0, NEXT_HOP_INVALID,
                                   &dpo_idx);

      /* the value we got when we registered */
      /*
       * This should be taken from the name?!? the index of the
       * object
       */
      dpo_set (&dpo,
               default_dpo.hicn_dpo_get_type (),
               (ip46_address_is_ip4 (&prefix->fp_addr) ? DPO_PROTO_IP4 :
                DPO_PROTO_IP6), dpo_idx);

      hicn_dpo_ctx_t * fib_entry = hicn_strategy_dpo_ctx_get(dpo_idx);

      fib_node_init (&fib_entry->fib_node, hicn_fib_node_type);
      fib_node_lock (&fib_entry->fib_node);

      fib_entry->fib_entry_index = fib_entry_track (fib_index,
                                                    prefix,
                                                    hicn_fib_node_type,
                                                    dpo_idx, &fib_entry->fib_sibling);


      /* Here is where we create the "via" like route */
      /*
       * For the moment we use the global one the prefix you want
       * to match Neale suggested -- FIB_SOURCE_HICN the client
       * that is adding them -- no easy explanation at this time…
       */
      CLIB_UNUSED (fib_node_index_t new_fib_node_index) =
        fib_table_entry_special_dpo_add (fib_hicn_index,
                                         prefix,
                                         hicn_fib_src,
                                         (FIB_ENTRY_FLAG_EXCLUSIVE |
                                          FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT),
                                         &dpo);

      sync_hicn_fib_entry(fib_entry);

      /* We added a route, therefore add one lock to the table */
      fib_table_lock (fib_index, prefix->fp_proto, hicn_fib_src);

      /* Enable the feature to punt data packet every time we enable a new hicn route
       * For each enable there must be a disable to defenitely disable the feature
       *
       * We cannot enable only the interfaces on which we send out interest because
       * Data packet  might be coming on in different interfaces, as in che case of mpls
       * tunnels (packets are received from the physical nic, not the mpls tunnel interface).
       */
      vnet_main_t * vnm = vnet_get_main ();
      vnet_sw_interface_walk(vnm, enable_data_receiving_new_fib_entry, &(prefix->fp_proto));

      dpo_unlock (&dpo);
    }
  else
    {
      const dpo_id_t *load_balance_dpo_id;
      const dpo_id_t *strategy_dpo_id;

      /* Route already existing. We need to update the dpo. */
      load_balance_dpo_id =
	fib_entry_contribute_ip_forwarding (fib_hicn_entry_index);

      /* The dpo is not a load balance dpo as expected */
      if (load_balance_dpo_id->dpoi_type != DPO_LOAD_BALANCE)
        {
          ret = HICN_ERROR_ROUTE_NO_LD;
          goto done;
        }
      else
	{
	  load_balance_t *lb =
	    load_balance_get (load_balance_dpo_id->dpoi_index);

          strategy_dpo_id = load_balance_get_bucket_i (lb, 0);

          if (!dpo_is_hicn (strategy_dpo_id))
            {
              ret = HICN_ERROR_ROUTE_DPO_NO_HICN;
              goto done;
            }

          if (lb->lb_n_buckets > 1)
            {
              ret = HICN_ERROR_ROUTE_MLT_LD;
              goto done;
            }

          hicn_dpo_ctx_t * hicn_fib_entry = hicn_strategy_dpo_ctx_get(strategy_dpo_id->dpoi_index);

          sync_hicn_fib_entry(hicn_fib_entry);
        }
    }

 done:
  return ret;
}

int
hicn_route_disable (fib_prefix_t *prefix) {

  int ret = HICN_ERROR_NONE;

  /* Check if the prefix is already enabled */
  u32 fib_hicn_index = fib_table_find(prefix->fp_proto, HICN_FIB_TABLE);

  fib_node_index_t fib_hicn_entry_index = fib_table_lookup_exact_match (fib_hicn_index, prefix);

  if (fib_hicn_entry_index == FIB_NODE_INDEX_INVALID)
    {
      return HICN_ERROR_ROUTE_NOT_FOUND;
    }
  else
    {
      const dpo_id_t *load_balance_dpo_id;
      const dpo_id_t *strategy_dpo_id;
      hicn_dpo_ctx_t * hicn_fib_entry;

      /* Route already existing. We need to update the dpo. */
      load_balance_dpo_id =
	fib_entry_contribute_ip_forwarding (fib_hicn_entry_index);

      /* The dpo is not a load balance dpo as expected */
      if (load_balance_dpo_id->dpoi_type != DPO_LOAD_BALANCE)
        {
          ret = HICN_ERROR_ROUTE_NO_LD;
          goto done;
        }
      else
	{
	  load_balance_t *lb =
	    load_balance_get (load_balance_dpo_id->dpoi_index);

          strategy_dpo_id = load_balance_get_bucket_i (lb, 0);

          if (!dpo_is_hicn (strategy_dpo_id))
            {
              ret = HICN_ERROR_ROUTE_DPO_NO_HICN;
              goto done;
            }

          if (lb->lb_n_buckets > 1)
            {
              ret = HICN_ERROR_ROUTE_MLT_LD;
              goto done;
            }

          hicn_fib_entry = hicn_strategy_dpo_ctx_get(strategy_dpo_id->dpoi_index);

          for (int i = 0; i < hicn_fib_entry->entry_count; i++)
            {
              hicn_strategy_dpo_ctx_del_nh(hicn_fib_entry->next_hops[i], hicn_fib_entry);
            }
        }

      fib_entry_untrack(hicn_fib_entry->fib_entry_index, hicn_fib_entry->fib_sibling);

      fib_table_entry_special_remove (fib_hicn_index, prefix, hicn_fib_src);

      /* Disable the feature to punt data packet every time we enable a new hicn route */
      vnet_main_t * vnm = vnet_get_main ();
      vnet_sw_interface_walk(vnm, disable_data_receiving_rm_fib_entry, &(prefix->fp_proto));
    }

 done:
  return ret;
}


static fib_node_t *
hicn_ctx_node_get (fib_node_index_t index)
{
  hicn_dpo_ctx_t * hicn_ctx;

  hicn_ctx = hicn_strategy_dpo_ctx_get(index);

  return (&hicn_ctx->fib_node);
}

static void
hicn_fib_last_lock_gone (fib_node_t *node)
{
}

static hicn_dpo_ctx_t *
hicn_ctx_from_fib_node (fib_node_t * node)
{
  return ((hicn_dpo_ctx_t *) (((char *) node) -
                              STRUCT_OFFSET_OF (hicn_dpo_ctx_t, fib_node)));
}

static fib_node_back_walk_rc_t
hicn_fib_back_walk_notify (fib_node_t *node,
                            fib_node_back_walk_ctx_t *ctx)
{

  hicn_dpo_ctx_t *fib_entry = hicn_ctx_from_fib_node (node);

  sync_hicn_fib_entry(fib_entry);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

static void
hicn_fib_show_memory (void)
{
}


static const fib_node_vft_t hicn_fib_vft =
{
 .fnv_get = hicn_ctx_node_get,
 .fnv_last_lock = hicn_fib_last_lock_gone,
 .fnv_back_walk = hicn_fib_back_walk_notify,
 .fnv_mem_show = hicn_fib_show_memory,
};

fib_table_walk_rc_t enable_data_on_existing_hicn(fib_node_index_t fei,
                                                 void *ctx)
{
  u32 sw_if = *(u32 *)ctx;
  const dpo_id_t *load_balance_dpo_id;
  const dpo_id_t *strategy_dpo_id;

  /* Route already existing. We need to update the dpo. */
  load_balance_dpo_id =
    fib_entry_contribute_ip_forwarding (fei);

  /* The dpo is not a load balance dpo as expected */
  if (load_balance_dpo_id->dpoi_type != DPO_LOAD_BALANCE)
    {
      goto done;
    }
  else
    {
      load_balance_t *lb =
        load_balance_get (load_balance_dpo_id->dpoi_index);

      strategy_dpo_id = load_balance_get_bucket_i (lb, 0);

      if (!dpo_is_hicn (strategy_dpo_id))
        {
          goto done;
        }

      enable_disable_data_receiving (strategy_dpo_id->dpoi_proto, sw_if, 1);
    }

 done:
  return (FIB_TABLE_WALK_CONTINUE);
}

static clib_error_t *
set_table_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{

  if (!is_add)
    return HICN_ERROR_NONE;

  int rv = ip_table_bind (FIB_PROTOCOL_IP4, sw_if_index, HICN_FIB_TABLE, 1);

  if (!rv)
    {
      rv = ip_table_bind (FIB_PROTOCOL_IP6, sw_if_index, HICN_FIB_TABLE, 1);

      if (rv)
        {
          /* An error occurred. Bind the interface back to the default fib */
          ip_table_bind (FIB_PROTOCOL_IP4, sw_if_index, 0, 1);
        }
    }

  u32 fib_index = fib_table_find(FIB_PROTOCOL_IP4,
                                 HICN_FIB_TABLE);
  if (fib_index != ~0)
    {
      /*
       * Walk the ip4 and ip6 fib tables to discover existing hicn fib entries.
       * For each of them we need to enable the feature to punt data packets.
       */
      fib_table_walk(fib_index,
                     FIB_PROTOCOL_IP4,
                     enable_data_on_existing_hicn,
                     &sw_if_index);
    }

  fib_index = fib_table_find(FIB_PROTOCOL_IP6,
                             HICN_FIB_TABLE);
  if (fib_index != ~0)
    {
      fib_table_walk(fib_index,
                     FIB_PROTOCOL_IP6,
                     enable_data_on_existing_hicn,
                     &sw_if_index);
    }

  return rv ? clib_error_return (0, "unable to add hicn table to interface") : 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (set_table_interface_add_del);

void
hicn_route_init ()
{
  vnet_main_t * vnm = vnet_get_main ();
  vlib_main_t * vm = vlib_get_main ();
  hicn_fib_src = fib_source_allocate ("hicn",
				      FIB_SOURCE_HICN, FIB_SOURCE_BH_API);

  hicn_fib_node_type = fib_node_register_new_type(&hicn_fib_vft);

  ip_table_create(FIB_PROTOCOL_IP4, HICN_FIB_TABLE, 1, (const u8 *)"hicn4");
  ip_table_create(FIB_PROTOCOL_IP6, HICN_FIB_TABLE, 1, (const u8 *)"hicn6");

  u32 sw_if_index;
  u8 mac_address[6];
  u8 is_specified = 0;
  u32 user_instance = 0;

  vnet_create_loopback_interface (&sw_if_index, mac_address,
                                  is_specified, user_instance);

  localhost4.as_u8[0] = 127;
  localhost4.as_u8[3] = 1;
  u32 length4 = 32, length6 = 128, is_del = 0, flags = 0;

  localhost6.as_u8[15] = 1;

  ip4_add_del_interface_address (vm, sw_if_index, &localhost4, length4, is_del);
  ip6_add_del_interface_address (vm, sw_if_index, &localhost6, length6, is_del);

  flags |= VNET_SW_INTERFACE_FLAG_ADMIN_UP;
  vnet_sw_interface_set_flags (vnm, sw_if_index, flags);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
