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

#ifndef __HICN_PARSER_H__
#define __HICN_PARSER_H__

#include <vlib/vlib.h>

#include "hicn.h"
#include "error.h"

/**
 * @file parser.h
 */

/*
 * Key type codes for header, header tlvs, body tlvs, and child tlvs
 */

// FIXME(reuse lib struct, no more control ?)
enum hicn_pkt_type_e
{
  HICN_PKT_TYPE_INTEREST = 0,
  HICN_PKT_TYPE_CONTENT = 1,
};

/**
 * @brief Parse an interest packet
 *
 * @param pkt vlib buffer holding the interest
 * @param name return variable that will point to the hicn name
 * @param namelen return valiable that will hold the length of the name
 * @param pkt_hdrp return valiable that will point to the packet header
 * @param isv6 return variable that will be equale to 1 is the header is ipv6
 */
always_inline int
hicn_interest_parse_pkt (vlib_buffer_t *pkt, hicn_name_t *name, u16 *namelen,
			 hicn_header_t **pkt_hdrp, u8 *isv6)
{
  if (pkt == NULL)
    return HICN_ERROR_PARSER_PKT_INVAL;
  hicn_header_t *pkt_hdr = vlib_buffer_get_current (pkt);
  *pkt_hdrp = pkt_hdr;
  u8 *ip_pkt = vlib_buffer_get_current (pkt);
  *isv6 = hicn_is_v6 (pkt_hdr);
  u8 ip_proto = (*isv6) * IPPROTO_IPV6;
  u8 next_proto_offset = 6 + (1 - *isv6) * 3;
  // in the ipv6 header the next header field is at byte 6
  // in the ipv4 header the protocol field is at byte 9
  hicn_type_t type = (hicn_type_t){ { .l4 = IPPROTO_NONE,
				      .l3 = IPPROTO_NONE,
				      .l2 = ip_pkt[next_proto_offset],
				      .l1 = ip_proto } };
  hicn_get_buffer (pkt)->type = type;

  hicn_ops_vft[type.l1]->get_interest_name (type, &pkt_hdr->protocol, name);
  *namelen = (1 - (*isv6)) * HICN_V4_NAME_LEN + (*isv6) * HICN_V6_NAME_LEN;

  return HICN_ERROR_NONE;
}

/**
 * @brief Parse a data packet
 *
 * @param pkt vlib buffer holding the interest
 * @param name return variable that will point to the hicn name
 * @param namelen return valiable that will hold the length of the name
 * @param pkt_hdrp return valiable that will point to the packet header
 * @param isv6 return variable that will be equale to 1 is the header is ipv6
 */
always_inline int
hicn_data_parse_pkt (vlib_buffer_t *pkt, hicn_name_t *name, u16 *namelen,
		     hicn_header_t **pkt_hdrp, u8 *isv6)
{
  if (pkt == NULL)
    return HICN_ERROR_PARSER_PKT_INVAL;
  hicn_header_t *pkt_hdr = vlib_buffer_get_current (pkt);
  *pkt_hdrp = pkt_hdr;
  *pkt_hdrp = pkt_hdr;
  u8 *ip_pkt = vlib_buffer_get_current (pkt);
  *isv6 = hicn_is_v6 (pkt_hdr);
  u8 ip_proto = (*isv6) * IPPROTO_IPV6;
  /*
   * in the ipv6 header the next header field is at byte 6 in the ipv4
   * header the protocol field is at byte 9
   */
  u8 next_proto_offset = 6 + (1 - *isv6) * 3;
  hicn_type_t type = (hicn_type_t){ { .l4 = IPPROTO_NONE,
				      .l3 = IPPROTO_NONE,
				      .l2 = ip_pkt[next_proto_offset],
				      .l1 = ip_proto } };
  hicn_get_buffer (pkt)->type = type;
  hicn_ops_vft[type.l1]->get_data_name (type, &pkt_hdr->protocol, name);
  *namelen = (1 - (*isv6)) * HICN_V4_NAME_LEN + (*isv6) * HICN_V6_NAME_LEN;

  return HICN_ERROR_NONE;
}

#endif /* // __HICN_PARSER_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
