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

#ifndef __HICN_PARSER_H__
#define __HICN_PARSER_H__

#include <vlib/vlib.h>

#include "hicn.h"
#include "error.h"

/**
 * @file parser.h
 */

/**
 * @brief Parse a interest packet
 *
 * @param pkt vlib buffer holding the interest
 * @param name [RETURNED] variable that will point to the hicn name
 * @param namelen [RETURNED] variable that will hold the length of the name
 * @param port [RETURNED] variable that will hold the source port of the packet
 * @param pkt_hdrp [RETURNED] valiable that will point to the packet header
 * @param isv6 [RETURNED] variable that will be equale to 1 is the header is
 * ipv6
 */
always_inline int
hicn_interest_parse_pkt (vlib_buffer_t *pkt)
{
  if (pkt == NULL)
    return HICN_ERROR_PARSER_PKT_INVAL;

  int ret = HICN_LIB_ERROR_NONE;

  hicn_header_t *pkt_hdr;
  u8 *ip_pkt;
  u8 ip_proto;
  u8 next_proto_offset;
  hicn_type_t type;
  hicn_name_t *name;
  u16 *port;
  int isv6;

  // start parsing first fields to get the protocols
  pkt_hdr = vlib_buffer_get_current (pkt);
  isv6 = hicn_is_v6 (pkt_hdr);

  ip_pkt = vlib_buffer_get_current (pkt);
  ip_proto = (1 - isv6) * IPPROTO_IP + (isv6) *IPPROTO_IPV6;

  // in the ipv6 header the next header field is at byte 6 in the ipv4
  // header the protocol field is at byte 9
  next_proto_offset = 6 + (1 - isv6) * 3;

  // get type info
  type.l4 = IPPROTO_NONE;
  type.l3 =
    ip_pkt[next_proto_offset] == IPPROTO_UDP ? IPPROTO_ENCAP : IPPROTO_NONE;
  type.l2 = ip_pkt[next_proto_offset];
  type.l1 = ip_proto;

  // cache hicn packet type in opaque2
  hicn_get_buffer (pkt)->type = type;

  // get name and name length
  name = &hicn_get_buffer (pkt)->name;
  ret =
    hicn_ops_vft[type.l1]->get_interest_name (type, &pkt_hdr->protocol, name);
  if (PREDICT_FALSE (ret))
    {
      if (type.l2 == IPPROTO_ICMPV4 || type.l2 == IPPROTO_ICMPV6)
	{
	  return HICN_ERROR_PARSER_MAPME_PACKET;
	}
      return HICN_ERROR_PARSER_PKT_INVAL;
    }

  // get source port
  port = &hicn_get_buffer (pkt)->port;
  hicn_ops_vft[type.l1]->get_source_port (type, &pkt_hdr->protocol, port);
  if (PREDICT_FALSE (ret))
    {
      return HICN_ERROR_PARSER_PKT_INVAL;
    }

  return ret;
}

/**
 * @brief Parse a data packet
 *
 * @param pkt vlib buffer holding the data
 * @param name [RETURNED] variable that will point to the hicn name
 * @param namelen [RETURNED] variable that will hold the length of the name
 * @param port [RETURNED] variable that will hold the source port of the packet
 * @param pkt_hdrp [RETURNED] valiable that will point to the packet header
 * @param isv6 [RETURNED] variable that will be equale to 1 is the header is
 * ipv6
 */
always_inline int
hicn_data_parse_pkt (vlib_buffer_t *pkt)
{
  if (pkt == NULL)
    return HICN_ERROR_PARSER_PKT_INVAL;

  int ret = HICN_LIB_ERROR_NONE;

  hicn_header_t *pkt_hdr;
  u8 *ip_pkt;
  u8 ip_proto;
  int isv6;
  u8 next_proto_offset;
  hicn_type_t type;
  hicn_name_t *name;
  u16 *port;

  // start parsing first fields to get the protocols
  pkt_hdr = vlib_buffer_get_current (pkt);
  isv6 = hicn_is_v6 (pkt_hdr);

  ip_pkt = vlib_buffer_get_current (pkt);
  ip_proto = (1 - isv6) * IPPROTO_IP + (isv6) *IPPROTO_IPV6;

  // in the ipv6 header the next header field is at byte 6 in the ipv4
  // header the protocol field is at byte 9
  next_proto_offset = 6 + (1 - isv6) * 3;

  // get type info
  type.l4 = IPPROTO_NONE;
  type.l3 =
    ip_pkt[next_proto_offset] == IPPROTO_UDP ? IPPROTO_ENCAP : IPPROTO_NONE;
  type.l2 = ip_pkt[next_proto_offset];
  type.l1 = ip_proto;

  // cache hicn packet type in opaque2
  hicn_get_buffer (pkt)->type = type;

  // get name and name length
  name = &hicn_get_buffer (pkt)->name;
  ret = hicn_ops_vft[type.l1]->get_data_name (type, &pkt_hdr->protocol, name);
  if (PREDICT_FALSE (ret))
    {
      if (type.l2 == IPPROTO_ICMPV4 || type.l2 == IPPROTO_ICMPV6)
	{
	  return HICN_ERROR_PARSER_MAPME_PACKET;
	}
      return HICN_ERROR_PARSER_PKT_INVAL;
    }

  // get source port
  port = &hicn_get_buffer (pkt)->port;
  hicn_ops_vft[type.l1]->get_source_port (type, &pkt_hdr->protocol, port);
  if (PREDICT_FALSE (ret))
    {
      return HICN_ERROR_PARSER_PKT_INVAL;
    }

  return ret;
}

#endif /* // __HICN_PARSER_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */