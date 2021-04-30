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

/**
 * @file mapme.c
 * @brief Implementation  of MAP-Me anchorless producer mobility management.
 */

#include <hicn/mapme.h>
#include <hicn/common.h>
#include <hicn/error.h>

#include <hicn/protocol/ipv4.h>
#include <hicn/protocol/ipv6.h>

size_t
hicn_mapme_v4_create_packet (u8 * buf, const hicn_prefix_t * prefix,
			     const mapme_params_t * params)
{
  hicn_mapme_v4_header_t *mh = (hicn_mapme_v4_header_t *) buf;
  /* *INDENT-OFF* */
  *mh = (hicn_mapme_v4_header_t) {
    .ip = {
      .version_ihl = (IPV4_DEFAULT_VERSION << 4) | (0x0f & IPV4_DEFAULT_IHL),
      .tos = IPV4_DEFAULT_TOS,
      .len = HICN_MAPME_V4_HDRLEN,
      .id = htons(IPV4_DEFAULT_ID),
      .frag_off = htons(IPV4_DEFAULT_FRAG_OFF),
      .ttl = HICN_MAPME_TTL,
      .protocol = IPPROTO_ICMP,
      .csum = 0,
      .saddr.as_u32 = 0,
      .daddr = prefix->name.ip4,
     },
    .icmp_rd = {
      .type = ((params->type == UPDATE) || (params->type == NOTIFICATION)) ? HICN_MAPME_ICMP_TYPE_IPV4 : HICN_MAPME_ICMP_TYPE_ACK_IPV4,
      .code = HICN_MAPME_ICMP_CODE,
      .csum = 0,
      .ip = prefix->name.ip4,
    },
    .seq = htonl(params->seq),
    .len = prefix->len,
  };
  /* *INDENT-ON* */

  return HICN_MAPME_V4_HDRLEN;
}

size_t
hicn_mapme_v6_create_packet (u8 * buf, const hicn_prefix_t * prefix,
			     const mapme_params_t * params)
{
  hicn_mapme_v6_header_t *mh = (hicn_mapme_v6_header_t *) buf;
  /* *INDENT-OFF* */
  *mh = (hicn_mapme_v6_header_t) {
    .ip = {
      .saddr = {{0}},
      .daddr = prefix->name.ip6,
      .version_class_flow = htonl(
          (IPV6_DEFAULT_VERSION       << 28) |
          (IPV6_DEFAULT_TRAFFIC_CLASS << 20) |
          (IPV6_DEFAULT_FLOW_LABEL     & 0xfffff)),
      .len = htons(HICN_MAPME_V6_HDRLEN - IPV6_HDRLEN),
      .nxt = IPPROTO_ICMPV6,
      .hlim = HICN_MAPME_TTL,
     },
    .icmp_rd = {
      .type = ((params->type == UPDATE) || (params->type == NOTIFICATION)) ? HICN_MAPME_ICMP_TYPE_IPV6 : HICN_MAPME_ICMP_TYPE_ACK_IPV6,
      .code = HICN_MAPME_ICMP_CODE,
      .csum = 0,
      .res = 0,
      .tgt = prefix->name.ip6,
      .dst = prefix->name.ip6,
    },
    .seq = htonl(params->seq),
    .len = prefix->len,
  };
  /* *INDENT-ON* */
  return HICN_MAPME_V6_HDRLEN;
}

size_t
hicn_mapme_create_packet (u8 * buf, const hicn_prefix_t * prefix,
			  const mapme_params_t * params)
{
  /* We currently ignore subsequent protocol definitions */
  if (PREDICT_TRUE (params->protocol == IPPROTO_IPV6))
    return hicn_mapme_v6_create_packet (buf, prefix, params);
  else
    return hicn_mapme_v4_create_packet (buf, prefix, params);
}

size_t
hicn_mapme_v4_create_ack (u8 * buf, const mapme_params_t * params)
{
  ip4_address_t tmp;		// tmp storage for swapping IP addresses for ACK

  hicn_mapme_v4_header_t *mh = (hicn_mapme_v4_header_t *) buf;
  tmp = mh->ip.daddr;
  mh->ip.daddr = mh->ip.saddr;
  mh->ip.saddr = tmp;
  mh->ip.ttl = HICN_MAPME_TTL;
  mh->icmp_rd.type = HICN_MAPME_ICMP_TYPE_ACK_IPV4;
  mh->icmp_rd.csum = 0;

  return HICN_MAPME_V4_HDRLEN;
}

size_t
hicn_mapme_v6_create_ack (u8 * buf, const mapme_params_t * params)
{
  ip6_address_t tmp;		// tmp storage for swapping IP addresses for ACK

  hicn_mapme_v6_header_t *mh = (hicn_mapme_v6_header_t *) buf;
  tmp = mh->ip.daddr;
  mh->ip.daddr = mh->ip.saddr;
  mh->ip.saddr = tmp;
  mh->ip.hlim = HICN_MAPME_TTL;
  mh->icmp_rd.type = HICN_MAPME_ICMP_TYPE_ACK_IPV6;
  mh->icmp_rd.csum = 0;

  return HICN_MAPME_V6_HDRLEN;
}

size_t
hicn_mapme_create_ack (u8 * buf, const mapme_params_t * params)
{
  /* We currently ignore subsequent protocol definitions */
  if (PREDICT_TRUE (params->protocol == IPPROTO_IPV6))
    return hicn_mapme_v6_create_ack (buf, params);
  else
    return hicn_mapme_v4_create_ack (buf, params);
}

int
hicn_mapme_v4_parse_packet (const u8 * packet, hicn_prefix_t * prefix,
			    mapme_params_t * params)
{
  hicn_mapme_v4_header_t *mh = (hicn_mapme_v4_header_t *) packet;

  /* *INDENT-OFF* */
  *prefix = (hicn_prefix_t) {
    .name = {
      .ip4 = HICN_MAPME_TYPE_IS_IU (mh->icmp_rd.type) ? mh->ip.daddr : mh->ip.saddr,
    },
    .len = mh->len,
  };

  *params = (mapme_params_t) {
    .protocol = IPPROTO_IP,
    .type = (mh->icmp_rd.type == HICN_MAPME_ICMP_TYPE_IPV4) ? UPDATE : UPDATE_ACK,
    .seq = ntohl (mh->seq),
  };
  /* *INDENT-ON* */

  return HICN_LIB_ERROR_NONE;
}

int
hicn_mapme_v6_parse_packet (const u8 * packet, hicn_prefix_t * prefix,
			    mapme_params_t * params)
{
  hicn_mapme_v6_header_t *mh = (hicn_mapme_v6_header_t *) packet;

  /* *INDENT-OFF* */
  *prefix = (hicn_prefix_t) {
    .name = {
      .ip6 = HICN_MAPME_TYPE_IS_IU (mh->icmp_rd.type) ? mh->ip.daddr : mh->ip.saddr,
    },
    .len = mh->len,
  };

  *params = (mapme_params_t) {
    .protocol = IPPROTO_IPV6,
    .type = (mh->icmp_rd.type == HICN_MAPME_ICMP_TYPE_IPV6) ? UPDATE : UPDATE_ACK,
    .seq = ntohl (mh->seq),
  };
  /* *INDENT-ON* */

  return HICN_LIB_ERROR_NONE;
}

int
hicn_mapme_parse_packet (const u8 * packet, hicn_prefix_t * prefix,
			 mapme_params_t * params)
{
  switch (HICN_IP_VERSION (packet))
    {
    case 4:
      return hicn_mapme_v4_parse_packet (packet, prefix, params);
    case 6:
      return hicn_mapme_v6_parse_packet (packet, prefix, params);
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
