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

#ifndef __HICN_UTILS_H__
#define __HICN_UTILS_H__

#include "hicn.h"

/**
 * @file
 *
 * Helpers to print hicn headers
 */

/**
 * @Brief Print the hicn name
 *
 * @param name hicn name to print
 */
always_inline void
hicn_print_name6 (hicn_name_t *name)
{
  u8 *s0;
  s0 = format (0, "Source addr %U, seq_number %u", format_ip6_address,
	       (ip6_address_t *) name->ip6.prefix,
	       clib_net_to_host_u32 (name->ip6.suffix));

  printf ("%s\n", s0);
}

/**
 * @Brief Print the ipv6 hicn header (src and dst address and port)
 *
 * @param hicn0 hICN header to print
 */
always_inline void
hicn_print6 (hicn_header_t *hicn0)
{
  vlib_main_t *vm = vlib_get_main ();
  u8 *s0;
  s0 = format (0, "Source addr %U:%u, dest addr %U:%u", format_ip6_address,
	       &(hicn0->v6.ip.saddr), clib_net_to_host_u32 (hicn0->v6.tcp.seq),
	       format_ip6_address, &(hicn0->v6.ip.daddr),
	       clib_net_to_host_u32 (hicn0->v6.tcp.seq));

  vlib_cli_output (vm, "%s\n", s0);
}

/**
 * @Brief Print the ipv4 hicn header (src and dst address and port)
 *
 * @param hicn0 hICN header to print
 */
always_inline void
hicn_print4 (hicn_header_t *hicn0)
{
  u8 *s0;
  s0 = format (0, "Source addr %U:%u, dest addr %U:%u", format_ip4_address,
	       &(hicn0->v4.ip.saddr), clib_net_to_host_u32 (hicn0->v4.tcp.seq),
	       format_ip4_address, &(hicn0->v4.ip.daddr),
	       clib_net_to_host_u32 (hicn0->v4.tcp.seq));

  printf ("%s\n", s0);
}

#endif /* // __HICN_UTILS_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
