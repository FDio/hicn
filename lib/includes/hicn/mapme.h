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

/**
 * @file mapme.h
 * @brief MAP-Me anchorless producer mobility management.
 */
#ifndef HICN_MAPME_H
#define HICN_MAPME_H

#include <stdint.h> // u32
#include <stdbool.h>

#include <hicn/name.h>

#include "common.h"

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

/* Should be moved to mapme.c, but header size still in use in VPP */

#define EXPECTED_MAPME_V4_HDRLEN 120
#define EXPECTED_MAPME_V6_HDRLEN 88

#endif /* HICN_MAPME_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
