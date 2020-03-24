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

/* Compute TCP checksum in software when offloading is disabled for a connection */

#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/tcp/tcp.h>

always_inline u16
ip6_tcp_compute_checksum_custom (vlib_main_t * vm, vlib_buffer_t * p0,
				 ip46_address_t * src, ip46_address_t * dst)
{
  ip_csum_t sum0;
  u16 payload_length_host_byte_order;
  u32 i;

  /* Initialize checksum with ip header. */
  sum0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, p0)) +
    clib_host_to_net_u16 (IP_PROTOCOL_TCP);
  payload_length_host_byte_order = vlib_buffer_length_in_chain (vm, p0);

  for (i = 0; i < ARRAY_LEN (src->ip6.as_uword); i++)
    {
      sum0 = ip_csum_with_carry
	(sum0, clib_mem_unaligned (&src->ip6.as_uword[i], uword));
      sum0 = ip_csum_with_carry
	(sum0, clib_mem_unaligned (&dst->ip6.as_uword[i], uword));
    }

  return ip_calculate_l4_checksum (vm, p0, sum0,
				   payload_length_host_byte_order, NULL, 0,
				   NULL);
}

always_inline u16
ip4_tcp_compute_checksum_custom (vlib_main_t * vm, vlib_buffer_t * p0,
				 ip46_address_t * src, ip46_address_t * dst)
{
  ip_csum_t sum0;
  u32 payload_length_host_byte_order;

  payload_length_host_byte_order = vlib_buffer_length_in_chain (vm, p0);
  sum0 =
    clib_host_to_net_u32 (payload_length_host_byte_order +
			  (IP_PROTOCOL_TCP << 16));

  sum0 = ip_csum_with_carry (sum0, clib_mem_unaligned (&src->ip4, u32));
  sum0 = ip_csum_with_carry (sum0, clib_mem_unaligned (&dst->ip4, u32));

  return ip_calculate_l4_checksum (vm, p0, sum0,
				   payload_length_host_byte_order, NULL, 0,
				   NULL);
}

always_inline u16
hicn_hs_compute_checksum (hicn_hs_ctx_t * ctx, vlib_buffer_t * b)
{
  u16 checksum = 0;
  if (PREDICT_FALSE (ctx->cfg_flags & HICN_HS_CFG_F_NO_CSUM_OFFLOAD))
    {
      hicn_hs_worker_t *wrk = hicn_hs_get_worker_by_context (ctx);
      vlib_main_t *vm = wrk->vm;
      ip46_address_t local_ip = {0};

      if (ctx->c_is_ip4)
	checksum = ip4_tcp_compute_checksum_custom
	  (vm, b, &local_ip, &ctx->c_rmt_ip);
      else
	checksum = ip6_tcp_compute_checksum_custom
	  (vm, b, &local_ip, &ctx->c_rmt_ip);
    }
  else
    {
      b->flags |= VNET_BUFFER_F_OFFLOAD_TCP_CKSUM;
    }
  return checksum;
}
