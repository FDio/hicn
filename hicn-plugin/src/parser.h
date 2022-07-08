/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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
#include "infra.h"

/**
 * @file parser.h
 */

#define PARSE(PACKET_TYPE, SIZE)                                              \
  do                                                                          \
    {                                                                         \
      if (pkt == NULL)                                                        \
	return HICN_ERROR_PARSER_PKT_INVAL;                                   \
                                                                              \
      int ret = HICN_ERROR_NONE;                                              \
                                                                              \
      u16 *port;                                                              \
      hicn_lifetime_t *lifetime;                                              \
      hicn_payload_type_t payload_type;                                       \
                                                                              \
      hicn_packet_buffer_t *pkbuf = &hicn_get_buffer (pkt)->pkbuf;            \
                                                                              \
      hicn_packet_set_buffer (pkbuf, vlib_buffer_get_current (pkt), (SIZE),   \
			      (SIZE));                                        \
      hicn_packet_analyze (&hicn_get_buffer (pkt)->pkbuf);                    \
                                                                              \
      /* get source port*/                                                    \
      port = &hicn_get_buffer (pkt)->port;                                    \
      hicn_packet_get_src_port (pkbuf, port);                                 \
      if (PREDICT_FALSE (ret))                                                \
	{                                                                     \
	  return HICN_ERROR_PARSER_PKT_INVAL;                                 \
	}                                                                     \
                                                                              \
      /* get lifetime*/                                                       \
      lifetime = &hicn_get_buffer (pkt)->lifetime;                            \
      hicn_packet_get_lifetime (pkbuf, lifetime);                             \
                                                                              \
      if (*lifetime > hicn_main.pit_lifetime_max_ms)                          \
	*lifetime = hicn_main.pit_lifetime_max_ms;                            \
                                                                              \
      /* get payload type */                                                  \
      hicn_packet_get_payload_type (pkbuf, &payload_type);                    \
      hicn_get_buffer (pkt)->payload_type = (u16) (payload_type);             \
      return ret;                                                             \
    }                                                                         \
  while (0)

#if 0
      hicn_name_t *name;                                                      \

      /* get name and name length*/
      name = &hicn_get_buffer (pkt)->name;
      ret = hicn_##PACKET_TYPE##_get_name (pkbuf, name);
      if (PREDICT_FALSE (ret))
	{
	  if (type.l2 == IPPROTO_ICMPV4 || type.l2 == IPPROTO_ICMPV6)
	    {
	      return HICN_ERROR_PARSER_MAPME_PACKET;
	    }
	  return HICN_ERROR_PARSER_PKT_INVAL;
	}
#endif

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
hicn_interest_parse_pkt (vlib_buffer_t *pkt, uword size)
{
  PARSE (interest, size);
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
hicn_data_parse_pkt (vlib_buffer_t *pkt, uword size)
{
  PARSE (data, size);
}

#endif /* __HICN_PARSER_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
