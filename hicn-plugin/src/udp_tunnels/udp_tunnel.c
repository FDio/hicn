/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <vppinfra/bihash_40_8.h>
#include <vnet/fib/fib_table.h>

#include "../error.h"
#include "../strategy_dpo_ctx.h"
#include "udp_tunnel.h"

clib_bihash_40_8_t udp_tunnels_hashtb;
dpo_type_t dpo_type_udp_ip4;
dpo_type_t dpo_type_udp_ip6;

u32 udp_tunnel_add (fib_protocol_t proto,
                    index_t fib_index,
                    const ip46_address_t * src_ip,
                    const ip46_address_t * dst_ip,
                    u16 src_port,
                    u16 dst_port,
                    udp_encap_fixup_flags_t flags)
{
  vlib_main_t *vm = vlib_get_main();
  clib_bihash_kv_40_8_t kv;
  clib_memcpy(&kv.key[0], src_ip, sizeof(ip46_address_t));
  clib_memcpy(&kv.key[2], dst_ip, sizeof(ip46_address_t));
  kv.key[4] = (clib_host_to_net_u16(src_port) << 16) + clib_host_to_net_u16(dst_port);

  clib_bihash_kv_40_8_t value;
  int rv = clib_bihash_search_40_8 (&udp_tunnels_hashtb, &kv, &value);

  if (rv != 0)
    {
      u32 uei = udp_encap_add_and_lock(proto, fib_index, src_ip, dst_ip, src_port, dst_port, flags);
      kv.value = uei;
      clib_bihash_add_del_40_8(&udp_tunnels_hashtb, &kv, 1);
      value.value = kv.value;
      if (proto == FIB_PROTOCOL_IP4)
        {
          udp_register_dst_port(vm, src_port, udp4_decap_node.index, 1);
        }
      else
        {
          udp_register_dst_port(vm, src_port, udp6_decap_node.index, 0);
        }
    }

  return value.value;
}

void udp_tunnel_add_existing (index_t uei, dpo_proto_t proto)
{
  vlib_main_t *vm = vlib_get_main();
  udp_encap_t * udp_encap = udp_encap_get(uei);
  clib_bihash_kv_40_8_t kv;

  ip46_address_t src = {0};
  ip46_address_t dst = {0};
  u16 src_port = 0, dst_port = 0;

  switch (proto)
    {
    case DPO_PROTO_IP4:
      ip46_address_set_ip4(&src, &(udp_encap->ue_hdrs.ip4.ue_ip4.src_address));
      ip46_address_set_ip4(&dst, &(udp_encap->ue_hdrs.ip4.ue_ip4.dst_address));
      src_port = udp_encap->ue_hdrs.ip4.ue_udp.src_port;
      dst_port = udp_encap->ue_hdrs.ip4.ue_udp.dst_port;
      break;
    case DPO_PROTO_IP6:
      ip46_address_set_ip6(&src, &(udp_encap->ue_hdrs.ip6.ue_ip6.src_address));
      ip46_address_set_ip6(&dst, &(udp_encap->ue_hdrs.ip6.ue_ip6.dst_address));
      src_port = udp_encap->ue_hdrs.ip6.ue_udp.src_port;
      dst_port = udp_encap->ue_hdrs.ip6.ue_udp.dst_port;
      break;
    default:
      break;
    }

  clib_memcpy(&kv.key[0], &src, sizeof(ip46_address_t));
  clib_memcpy(&kv.key[2], &dst, sizeof(ip46_address_t));
  kv.key[4] = (src_port << 16) + dst_port ;
  kv.value = uei;

  clib_bihash_add_del_40_8(&udp_tunnels_hashtb, &kv, 1);

  if (proto == DPO_PROTO_IP4)
    {
      udp_register_dst_port(vm, src_port, udp4_decap_node.index, 1);
    }
  else
    {
      udp_register_dst_port(vm, src_port, udp6_decap_node.index, 0);
    }
}

int udp_tunnel_del (fib_protocol_t proto,
                    index_t fib_index,
                    const ip46_address_t * src_ip,
                    const ip46_address_t * dst_ip,
                    u16 src_port,
                    u16 dst_port,
                    udp_encap_fixup_flags_t flags)
{
  clib_bihash_kv_40_8_t kv;
  clib_memcpy(&kv.key[0], src_ip, sizeof(ip46_address_t));
  clib_memcpy(&kv.key[2], dst_ip, sizeof(ip46_address_t));
  kv.key[4] = (src_port << 16) + dst_port;

  clib_bihash_kv_40_8_t value;
  int ret = clib_bihash_search_40_8 (&udp_tunnels_hashtb, &kv, &value);

  if (ret == 0)
    {
      udp_encap_unlock((u32)value.value);
      clib_bihash_add_del_40_8(&udp_tunnels_hashtb, &kv, 0);
      ret = HICN_ERROR_NONE;
    }
  else
    {
      ret = HICN_ERROR_UDP_TUNNEL_NOT_FOUND;
    }

  return HICN_ERROR_NONE;
}

u32 udp_tunnel_get(const ip46_address_t * src_ip,
                   const ip46_address_t * dst_ip,
                   u16 src_port,
                   u16 dst_port)
{
  clib_bihash_kv_40_8_t kv;
  clib_memcpy(&kv.key[0], src_ip, sizeof(ip46_address_t));
  clib_memcpy(&kv.key[2], dst_ip, sizeof(ip46_address_t));
  kv.key[4] = (src_port << 16) + dst_port;

  clib_bihash_kv_40_8_t value;
  int ret = clib_bihash_search_40_8 (&udp_tunnels_hashtb, &kv, &value);

  return ret == 0 ? (u32)value.value : UDP_TUNNEL_INVALID;
}


void udp_tunnel_init()
{
  clib_bihash_init_40_8(&udp_tunnels_hashtb, "udp encap table",
                        2048, 256 << 20);

  /*
   * Udp encap does not expose the dpo type when it registers.
   * In the following we understand what is the dpo type for a udp_encap dpo.
   */
  ip46_address_t src = {0};
  ip46_address_t dst = {0};

  src.ip6.as_u8[15] = 1;
  dst.ip6.as_u8[15] = 2;

  u32 fib_index = fib_table_find (FIB_PROTOCOL_IP6, HICN_FIB_TABLE);
  u32 uei = udp_encap_add_and_lock(FIB_PROTOCOL_IP6, fib_index, &src, &dst, 4444, 4444, UDP_ENCAP_FIXUP_NONE);

  dpo_id_t temp;
  udp_encap_contribute_forwarding(uei, DPO_PROTO_IP6, &temp);
  dpo_type_udp_ip6 = temp.dpoi_type;
  udp_encap_unlock(uei);


  fib_index = fib_table_find (FIB_PROTOCOL_IP4, HICN_FIB_TABLE);
  uei = udp_encap_add_and_lock(FIB_PROTOCOL_IP4, fib_index, &src, &dst, 4444, 4444, UDP_ENCAP_FIXUP_NONE);
  udp_encap_contribute_forwarding(uei, DPO_PROTO_IP4, &temp);
  dpo_type_udp_ip4 = temp.dpoi_type;
  udp_encap_unlock(uei);
}

static clib_error_t *
udp_tunnel_command_fn (vlib_main_t * vm,
			       unformat_input_t * main_input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  ip46_address_t src_ip, dst_ip;
  u32 table_id, src_port, dst_port;
  fib_protocol_t fproto;
  u8 is_del;
  index_t uei;

  is_del = 0;
  fproto = FIB_PROTOCOL_MAX;
  uei = ~0;
  table_id = HICN_FIB_TABLE;

  /* Get a line of input. */
  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
          if (unformat (line_input, "index %d", &uei))
            ;
          else if (unformat (line_input, "add"))
            is_del = 0;
          else if (unformat (line_input, "del"))
            is_del = 1;
          else if (unformat (line_input, "%U %U",
                             unformat_ip4_address,
                             &src_ip.ip4, unformat_ip4_address, &dst_ip.ip4))
            fproto = FIB_PROTOCOL_IP4;
          else if (unformat (line_input, "%U %U",
                             unformat_ip6_address,
                             &src_ip.ip6, unformat_ip6_address, &dst_ip.ip6))
            fproto = FIB_PROTOCOL_IP6;
          else if (unformat (line_input, "%d %d", &src_port, &dst_port))
            ;
          else if (unformat (line_input, "table-id %d", &table_id))
            ;
          else
            {
              error = unformat_parse_error (line_input);
              goto done;
            }
	}
    }

  if (!is_del && fproto != FIB_PROTOCOL_MAX)
    {
      index_t uei;
      index_t fib_index = fib_table_find (fproto, HICN_FIB_TABLE);
      if (~0 == fib_index)
	{
	  error = clib_error_return (0, "Nonexistent table id %d", table_id);
	  goto done;
	}
      uei = udp_tunnel_add(fproto, fib_index, &src_ip, &dst_ip, src_port, dst_port, UDP_ENCAP_FIXUP_NONE);

      vlib_cli_output (vm, "udp-encap: %d\n", uei);
    }
  else if (is_del)
    {
      if (INDEX_INVALID == uei)
	{
	  error = clib_error_return (0, "specify udp-encap object index");
	  goto done;
	}
      udp_encap_unlock (uei);
    }
  else
    {
      error = clib_error_return (0, "specify some IP addresses");
    }

 done:
  unformat_free (line_input);
  return error;

}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (udp_tunnel_command, static) =
  {
   .path = "udp tunnel",
   .short_help = "udp tunnel [add/del] src_address dst_address src_port dst_port",
   .function = udp_tunnel_command_fn,
  };
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
