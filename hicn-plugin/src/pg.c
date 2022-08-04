/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_entry_track.h>

#include "hicn.h"
#include "pg.h"
#include "parser.h"
#include "infra.h"
#include "route.h"

hicnpg_main_t hicnpg_main = { .index = (u32) 0,
			      .index_ifaces = (u32) 1,
			      .max_seq_number = (u32) ~0,
			      .interest_lifetime = 4,
			      .n_flows = (u32) 0,
			      .n_ifaces = (u32) 1,
			      .sw_if = (u32) 0 };

/**
 * Pool of hicnpg_server_t
 */
hicnpg_server_t *hicnpg_server_pool;

/*
 * hicnph servrer FIB node type
 */
fib_node_type_t hicnpg_server_fib_node_type;

/**
 * Registered DPO type.
 */
dpo_type_t hicnpg_server_dpo_type;

static void
hicnpg_server_restack (hicnpg_server_t *hicnpg_server)
{
  dpo_stack (
    hicnpg_server_dpo_type, fib_proto_to_dpo (hicnpg_server->prefix.fp_proto),
    &hicnpg_server->dpo,
    fib_entry_contribute_ip_forwarding (hicnpg_server->fib_entry_index));
}

static hicnpg_server_t *
hicnpg_server_from_fib_node (fib_node_t *node)
{
#if 1
  ASSERT (hicnpg_server_fib_node_type == node->fn_type);
  return ((hicnpg_server_t *) (((char *) node) -
			       STRUCT_OFFSET_OF (hicnpg_server_t, fib_node)));
#else
  hicn_header_t *h0 = vlib_buffer_get_current (b0);

  /* Generate the right src and dst corresponding to flow and iface */
  ip46_address_t src_addr = {
    .ip4 = hicnpg_main.pgen_clt_src_addr.ip4,
  };
  hicn_name_t dst_name = {
    .prefix.v4.as_u32 = hicnpg_main.pgen_clt_hicn_name->fp_addr.ip4.as_u32,
    .suffix = seq_number,
  };

  src_addr.ip4.as_u32 += clib_host_to_net_u32 (iface);
  dst_name.prefix.v4.as_u32 += clib_net_to_host_u32 (next_flow);

  /* Update locator and name */
  hicn_type_t type = hicn_get_buffer (b0)->type;
  HICN_OPS4->set_interest_locator (type, &h0->protocol,
				   (hicn_ip_address_t *) &src_addr);
  HICN_OPS4->set_interest_name (type, &h0->protocol, &dst_name);

  /* Update lifetime  (currently L4 checksum is not updated) */
  HICN_OPS4->set_lifetime (type, &h0->protocol, interest_lifetime);

  /* Update checksums */
  HICN_OPS4->update_checksums (type, &h0->protocol, 0, 0);
#endif
}

/**
 * Function definition to backwalk a FIB node
 */
static fib_node_back_walk_rc_t
hicnpg_server_fib_back_walk (fib_node_t *node, fib_node_back_walk_ctx_t *ctx)
{
  hicnpg_server_restack (hicnpg_server_from_fib_node (node));

#if 1
  return FIB_NODE_BACK_WALK_CONTINUE;
#else
  /* Generate the right src and dst corresponding to flow and iface */
  ip46_address_t src_addr = {
    .ip6 = hicnpg_main.pgen_clt_src_addr.ip6,
  };
  hicn_name_t dst_name = {
    .prefix.v6.as_u64 = {
        hicnpg_main.pgen_clt_hicn_name->fp_addr.ip6.as_u64[0],
        hicnpg_main.pgen_clt_hicn_name->fp_addr.ip6.as_u64[1],
    },
    .suffix = seq_number,
  };
  src_addr.ip6.as_u32[3] += clib_host_to_net_u32 (iface);
  dst_name.prefix.v6.as_u32[3] += clib_net_to_host_u32 (next_flow);

  /* Update locator and name */
  hicn_type_t type = hicn_get_buffer (b0)->type;
  HICN_OPS6->set_interest_locator (type, &h0->protocol,
				   (hicn_ip_address_t *) &src_addr);
  HICN_OPS6->set_interest_name (type, &h0->protocol, &dst_name);

  /* Update lifetime */
  HICN_OPS6->set_lifetime (type, &h0->protocol, interest_lifetime);

  /* Update checksums */
  calculate_tcp_checksum_v6 (vm, b0);
#endif
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
hicnpg_server_fib_node_get (fib_node_index_t index)
{
  hicnpg_server_t *hpg_server;

  hpg_server = pool_elt_at_index (hicnpg_server_pool, index);

  return (&hpg_server->fib_node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
hicnpg_server_fib_last_lock_gone (fib_node_t *node)
{
  hicnpg_server_t *hpg_server;

  hpg_server = hicnpg_server_from_fib_node (node);

  /**
   * reset the stacked DPO to unlock it
   */
  dpo_reset (&hpg_server->dpo);

  pool_put (hicnpg_server_pool, hpg_server);
}

static void
hicnpg_server_dpo_lock (dpo_id_t *dpo)
{
  hicnpg_server_t *hpg_server;
  hpg_server = hicnpg_server_get (dpo->dpoi_index);
  fib_node_lock (&hpg_server->fib_node);
}

static void
hicnpg_server_dpo_unlock (dpo_id_t *dpo)
{
  hicnpg_server_t *hpg_server;
  hpg_server = hicnpg_server_get (dpo->dpoi_index);
  fib_node_unlock (&hpg_server->fib_node);
}

static u8 *
format_hicnpg_server_i (u8 *s, va_list *args)
{
  index_t hicnpg_server_i = va_arg (*args, index_t);
  //   u32 indent = va_arg (*args, u32);
  u32 details = va_arg (*args, u32);
  //   vlib_counter_t to;
  hicnpg_server_t *hpg;

  hpg = hicnpg_server_get (hicnpg_server_i);

  // FIXME
  s = format (s, "dpo-hicnpg-server:[%d]: ip-fib-index:%d ", hicnpg_server_i,
	      hpg->fib_index);

  if (FIB_PROTOCOL_IP4 == hpg->prefix.fp_proto)
    {
      s = format (s, "protocol:FIB_PROTOCOL_IP4  prefix: %U",
		  format_fib_prefix, &hpg->prefix);
    }
  else
    {
      s = format (s, "protocol:FIB_PROTOCOL_IP6  prefix: %U",
		  format_fib_prefix, &hpg->prefix);
    }

#if 0
  vlib_get_combined_counter (&(udp_encap_counters), uei, &to);
  s = format (s, " to:[%Ld:%Ld]]", to.packets, to.bytes);s
#endif

  if (details)
    {
      s = format (s, " locks:%d", hpg->fib_node.fn_locks);
      //       s = format (s, "\n%UStacked on:", format_white_space, indent +
      //       1); s = format (s, "\n%U%U", format_white_space, indent + 2,
      //       format_dpo_id,
      // 		  &hpg->dpo, indent + 3);
    }

  return s;
}

static u8 *
format_hicnpg_server_dpo (u8 *s, va_list *args)
{
  index_t hpg_server_i = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);

  return (format (s, "%U", format_hicnpg_server_i, hpg_server_i, indent, 1));
}

/*
 * Virtual function table registered by hicn pg server
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t hicnpg_server_fib_vft = {
  .fnv_get = hicnpg_server_fib_node_get,
  .fnv_last_lock = hicnpg_server_fib_last_lock_gone,
  .fnv_back_walk = hicnpg_server_fib_back_walk,
};

const static dpo_vft_t hicnpg_server_dpo_vft = {
  .dv_lock = hicnpg_server_dpo_lock,
  .dv_unlock = hicnpg_server_dpo_unlock,
  .dv_format = format_hicnpg_server_dpo,
};

const static char *const hicnpg_server_ip4_nodes[] = {
  "hicnpg-server-4",
  NULL,
};

const static char *const hicnpg_server_ip6_nodes[] = {
  "hicnpg-server-6",
  NULL,
};

const static char *const *const hicnpg_server_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = hicnpg_server_ip4_nodes,
  [DPO_PROTO_IP6] = hicnpg_server_ip6_nodes
};

clib_error_t *
hicnpg_server_add_and_lock (fib_prefix_t *prefix, u32 *hicnpg_server_index,
			    ip46_address_t *locator, size_t payload_size)
{
  hicnpg_server_t *hpg;
  index_t hpgi;
  u32 fib_index;
  fib_node_index_t fib_entry_index;
  u32 buffer_index;
  vlib_buffer_t *rb = NULL;

  // Retrieve hicn fib table
  fib_index =
    fib_table_find_or_create_and_lock (prefix->fp_proto, 0, hicn_fib_src);

  // Check the prefix we are adding is not already in the table
  fib_entry_index = fib_table_lookup_exact_match (fib_index, prefix);

  if (fib_entry_index != FIB_NODE_INDEX_INVALID)
    {
      // Route already existing.
      return clib_error_return (0, "Route exist already.");
    }

  // Allocate packet buffer
  int n_buf = vlib_buffer_alloc (vlib_get_main (), &buffer_index, 1);

  if (n_buf == 0)
    {
      return clib_error_return (0, "Impossible to allocate paylod buffer.");
    }

  // Initialize the buffer data with zeros
  rb = vlib_get_buffer (vlib_get_main (), buffer_index);
  memset (rb->data, 0, payload_size);
  rb->current_length = payload_size;

  // We can proceed. Get a new hicnpg_server_t
  pool_get_aligned_zero (hicnpg_server_pool, hpg, 2 * CLIB_CACHE_LINE_BYTES);
  hpgi = hpg - hicnpg_server_pool;

  // Set DPO
  dpo_set (
    &hpg->dpo, hicnpg_server_dpo_type,
    (ip46_address_is_ip4 (&prefix->fp_addr) ? DPO_PROTO_IP4 : DPO_PROTO_IP6),
    hpgi);

  // Add the route via the hicnpg_server_dpo_type. In this way packets will
  // endup in the hicnpg_server node
  CLIB_UNUSED (fib_node_index_t new_fib_node_index) =
    fib_table_entry_special_dpo_add (
      fib_index, prefix, hicn_fib_src,
      (FIB_ENTRY_FLAG_EXCLUSIVE | FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT),
      &hpg->dpo);

#if 0
  vlib_validate_combined_counter (&(udp_encap_counters), uei);
  vlib_zero_combined_counter (&(udp_encap_counters), uei);
#endif

  // Init remaining struct fields
  fib_node_init (&hpg->fib_node, hicnpg_server_fib_node_type);
  fib_node_lock (&hpg->fib_node);
  hpg->fib_index = fib_index;
  hpg->prefix = *prefix;
  hpg->buffer_index = buffer_index;
  hpg->fib_entry_index = fib_entry_index;
  hpg->hicn_locator = *locator;

  // track the destination address
  //   hpg->fib_entry_index =
  //     fib_entry_track (fib_index, &hpg->prefix,
  // 		     hicnpg_server_fib_node_type, hpgi, &hpg->fib_sibling);
  //   hicnpg_server_restack (hpg);

  HICN_DEBUG ("Calling hicn enable for pg-server face");

  hicn_face_id_t *vec_faces = NULL;
  hicn_route_enable (prefix, &vec_faces);
  if (vec_faces != NULL)
    vec_free (vec_faces);

  // Return the index of the hicnpg_server_t
  *hicnpg_server_index = hpgi;

  return NULL;
}

clib_error_t *
hicn_pg_init (vlib_main_t *vm)
{
  hicnpg_server_fib_node_type = fib_node_register_new_type (
    "hicnpg_server_fib_node", &hicnpg_server_fib_vft);

  hicnpg_server_dpo_type =
    dpo_register_new_type (&hicnpg_server_dpo_vft, hicnpg_server_nodes);

  return NULL;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
