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

/**
 * @file mapme.c
 * @brief Implementation  of MAP-Me anchorless producer mobility management.
 */

#include <hicn/mapme.h>
#include <hicn/common.h>
#include <hicn/error.h>

#include "protocol/ipv4.h"
#include "protocol/ipv6.h"
#include "protocol/icmprd.h"

/** @brief MAP-Me packet header for IPv4 */
typedef struct
{
  _ipv4_header_t ip;
  _icmprd4_header_t icmp_rd;
  seq_t seq;
  u8 len;
  u8 _pad[3];
} hicn_mapme_v4_header_t;

/** @brief MAP-Me packet header for IPv6 */
typedef struct
{
  _ipv6_header_t ip;
  _icmprd_header_t icmp_rd;
  seq_t seq;
  u8 len;
  u8 _pad[3];
} hicn_mapme_v6_header_t;

/** @brief MAP-Me packet header (IP version agnostic) */
typedef union
{
  hicn_mapme_v4_header_t v4;
  hicn_mapme_v6_header_t v6;
} hicn_mapme_header_t;

#define HICN_MAPME_V4_HDRLEN sizeof (hicn_mapme_v4_header_t)
#define HICN_MAPME_V6_HDRLEN sizeof (hicn_mapme_v6_header_t)

static_assert (EXPECTED_MAPME_V4_HDRLEN == HICN_MAPME_V4_HDRLEN,
	       "Size of MAPME_V4 struct does not match its expected size.");
static_assert (EXPECTED_MAPME_V6_HDRLEN == HICN_MAPME_V6_HDRLEN,
	       "Size of MAPME_V6 struct does not match its expected size.");

size_t
hicn_mapme_v4_create_packet (u8 *buf, const hicn_prefix_t *prefix,
			     const mapme_params_t *params)
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
      .saddr.as_u32 = IPV4_LOOPBACK.v4.as_u32,
      .daddr = prefix->name.v4,
     },
    .icmp_rd = {
      .type = ((params->type == UPDATE) || (params->type == NOTIFICATION)) ? HICN_MAPME_ICMP_TYPE_IPV4 : HICN_MAPME_ICMP_TYPE_ACK_IPV4,
      .code = HICN_MAPME_ICMP_CODE,
      .csum = 0,
      .ip = prefix->name.v4,
    },
    .seq = htonl(params->seq),
    .len = prefix->len,
  };
  /* *INDENT-ON* */

  return HICN_MAPME_V4_HDRLEN;
}

size_t
hicn_mapme_v6_create_packet (u8 *buf, const hicn_prefix_t *prefix,
			     const mapme_params_t *params)
{
  hicn_mapme_v6_header_t *mh = (hicn_mapme_v6_header_t *) buf;
  /* *INDENT-OFF* */
  *mh = (hicn_mapme_v6_header_t) {
    .ip = {
      .saddr = IPV6_LOOPBACK.v6,
      .daddr = prefix->name.v6,
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
      .tgt = prefix->name.v6,
      .dst = prefix->name.v6,
    },
    .seq = htonl(params->seq),
    .len = prefix->len,
  };
  /* *INDENT-ON* */
  return HICN_MAPME_V6_HDRLEN;
}

size_t
hicn_mapme_create_packet (u8 *buf, const hicn_prefix_t *prefix,
			  const mapme_params_t *params)
{
  /* We currently ignore subsequent protocol definitions */
  if (HICN_EXPECT_TRUE (params->protocol == IPPROTO_IPV6))
    return hicn_mapme_v6_create_packet (buf, prefix, params);
  else
    return hicn_mapme_v4_create_packet (buf, prefix, params);
}

size_t
hicn_mapme_v4_create_ack (u8 *buf, const mapme_params_t *params)
{
  ipv4_address_t tmp; // tmp storage for swapping IP addresses for ACK

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
hicn_mapme_v6_create_ack (u8 *buf, const mapme_params_t *params)
{
  ipv6_address_t tmp; // tmp storage for swapping IP addresses for ACK

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
hicn_mapme_create_ack (u8 *buf, const mapme_params_t *params)
{
  /* We currently ignore subsequent protocol definitions */
  if (HICN_EXPECT_TRUE (params->protocol == IPPROTO_IPV6))
    return hicn_mapme_v6_create_ack (buf, params);
  else
    return hicn_mapme_v4_create_ack (buf, params);
}

int
hicn_mapme_v4_parse_packet (const u8 *packet, hicn_prefix_t *prefix,
			    mapme_params_t *params)
{
  hicn_mapme_v4_header_t *mh = (hicn_mapme_v4_header_t *) packet;

  /* *INDENT-OFF* */
  *prefix = (hicn_prefix_t) {
    .name = {
      .v4 = HICN_MAPME_TYPE_IS_IU (mh->icmp_rd.type) ? mh->ip.daddr : mh->ip.saddr,
    },
    .len = mh->len,
  };

  *params = (mapme_params_t){
    .protocol = IPPROTO_IP,
    .type =
      (mh->icmp_rd.type == HICN_MAPME_ICMP_TYPE_IPV4) ? UPDATE : UPDATE_ACK,
    .seq = ntohl (mh->seq),
  };
  /* *INDENT-ON* */

  return HICN_LIB_ERROR_NONE;
}

int
hicn_mapme_v6_parse_packet (const u8 *packet, hicn_prefix_t *prefix,
			    mapme_params_t *params)
{
  hicn_mapme_v6_header_t *mh = (hicn_mapme_v6_header_t *) packet;

  /* *INDENT-OFF* */
  *prefix = (hicn_prefix_t) {
    .name = {
      .v6 = HICN_MAPME_TYPE_IS_IU (mh->icmp_rd.type) ? mh->ip.daddr : mh->ip.saddr,
    },
    .len = mh->len,
  };

  *params = (mapme_params_t){
    .protocol = IPPROTO_IPV6,
    .type =
      (mh->icmp_rd.type == HICN_MAPME_ICMP_TYPE_IPV6) ? UPDATE : UPDATE_ACK,
    .seq = ntohl (mh->seq),
  };
  /* *INDENT-ON* */

  return HICN_LIB_ERROR_NONE;
}

int
hicn_mapme_parse_packet (const u8 *packet, hicn_prefix_t *prefix,
			 mapme_params_t *params)
{
  switch (HICN_IP_VERSION (packet))
    {
    case 4:
      return hicn_mapme_v4_parse_packet (packet, prefix, params);
    case 6:
      return hicn_mapme_v6_parse_packet (packet, prefix, params);
    default:
      break;
    }
  return HICN_LIB_ERROR_UNEXPECTED;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
