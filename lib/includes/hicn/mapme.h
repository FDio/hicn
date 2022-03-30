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
 * @file mapme.h
 * @brief MAP-Me anchorless producer mobility management.
 */
#ifndef HICN_MAPME_H
#define HICN_MAPME_H

#include <stdint.h> // u32
#include <stdbool.h>

#include "common.h"
#include "protocol.h"
#include "ops.h"

/**
 * @brief MAP-Me configuration options
 */
typedef struct
{
  /** MAP-Me enabled flag (default: false) */
  bool enabled;
  /** timescale (T_U parameter) in ms (default: 0 for no notifications) */
  u32 timescale;
  /** retransmission timer in ms (default: 50) */
  u32 retx;
  /**
   * Discovery enabled flag (default: true, should be true if mandatory is
   * notifications are enabled)
   */
  bool discovery;
} hicn_mapme_conf_t;

/** @brief Default MAP-Me configuration */
static const hicn_mapme_conf_t hicn_mapme_conf = {
  ATTR_INIT (enabled, false),
  ATTR_INIT (timescale, 0),
  ATTR_INIT (retx, 50),
  ATTR_INIT (discovery, true),
};

/** @brief MAP-Me update sequence number */
typedef u32 seq_t;

/** @brief MAP-Me packet types */
typedef enum
{
  UNKNOWN,
  UPDATE,
  UPDATE_ACK,
  NOTIFICATION,
  NOTIFICATION_ACK,
} hicn_mapme_type_t;

/** @brief MAP-Me parameters (excluding those contained in * hicn_prefix_t) */
typedef struct
{
  int protocol;
  hicn_mapme_type_t type;
  seq_t seq;
} mapme_params_t;

/* MAP-Me API */
size_t hicn_mapme_create_packet (u8 *buf, const hicn_prefix_t *prefix,
				 const mapme_params_t *params);
size_t hicn_mapme_create_ack (u8 *buf, const mapme_params_t *params);
int hicn_mapme_parse_packet (const u8 *packet, hicn_prefix_t *prefix,
			     mapme_params_t *params);

/* Implementation & parsing : ICMP Redirect */

#define HICN_MAPME_ACK_FLAG (0x20 | 0x60)

#define HICN_MAPME_ICMP_TYPE_IPV4 5
#define HICN_MAPME_ICMP_TYPE_IPV6 137
#define HICN_MAPME_ICMP_TYPE_ACK_IPV4                                         \
  (HICN_MAPME_ICMP_TYPE_IPV4 | HICN_MAPME_ACK_FLAG)
#define HICN_MAPME_ICMP_TYPE_ACK_IPV6                                         \
  (HICN_MAPME_ICMP_TYPE_IPV6 | HICN_MAPME_ACK_FLAG)
#define HICN_MAPME_ICMP_CODE                                                  \
  0 /* Redirect Datagrams for the Network (or subnet) */

#define HICN_MAPME_TYPE_IS_IU(type)                                           \
  ((type == HICN_MAPME_ICMP_TYPE_IPV4) || (type == HICN_MAPME_ICMP_TYPE_IPV6))
#define HICN_MAPME_TYPE_IS_IU_ACK(type)                                       \
  ((type == HICN_MAPME_ICMP_TYPE_ACK_IPV4) ||                                 \
   (type == HICN_MAPME_ICMP_TYPE_ACK_IPV6))

#define HICN_MAPME_IS_IU(type, code)                                          \
  (HICN_MAPME_TYPE_IS_IU (type) && (code == HICN_MAPME_ICMP_CODE))
#define HICN_MAPME_IS_ACK(type, code)                                         \
  (HICN_MAPME_TYPE_IS_IU_ACK (type) && (code == HICN_MAPME_ICMP_CODE))

#define HICN_IS_MAPME(type, code)                                             \
  (HICN_MAPME_IS_IU (type, code) || HICN_MAPME_IS_ACK (type, code))

/* Fast check for ACK flag */
#define HICN_MAPME_IS_ACK_FAST(icmp_type) (icmp_type & HICN_MAPME_ACK_FLAG)

/* Default TTL */
#define HICN_MAPME_TTL 255 // typical for redirect (ref?)

/*
 * The length of the MAPME4 header struct must be 120 bytes.
 */
#define EXPECTED_MAPME_V4_HDRLEN 120

/** @brief MAP-Me packet header for IPv4 */
typedef struct
{
  _ipv4_header_t ip;
  _icmprd4_header_t icmp_rd;
  seq_t seq;
  u8 len;
  u8 _pad[3];
} hicn_mapme_v4_header_t;

/*
 * The length of the MAPME4 header struct must be  bytes.
 */
#define EXPECTED_MAPME_V6_HDRLEN 88

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

#endif /* HICN_MAPME_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
