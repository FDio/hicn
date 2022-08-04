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
 * @file base.h
 * @brief Base hICN definitions.
 */

#ifndef HICN_BASE_H
#define HICN_BASE_H

#include <stdio.h>
#include <stdbool.h>
#include "common.h"
#ifdef _WIN32
#include <Winsock2.h>
#else
#include <netinet/in.h>
#endif
/* Default header fields */
#define HICN_DEFAULT_TTL 254

#define SYMBOLIC_NAME_LEN 16

/* hICN attribute types */

/* Face id */

typedef u32 hicn_faceid_t;

/* Lifetime */

typedef u32 hicn_lifetime_t;

#define HICN_MAX_LIFETIME_SCALED     0xFFFF
#define HICN_MAX_LIFETIME_MULTIPLIER 0x0F /* 4 bits */
#define HICN_MAX_LIFETIME                                                     \
  HICN_MAX_LIFETIME_SCALED << HICN_MAX_LIFETIME_MULTIPLIER

/**
 * @brief hICN packet format type
 *
 * The hICN type represents the sequence of protocols that we can find in
 * packet headers. They are represented as a quartet of u8 values, correponding
 * to IANA protocol assignment, and read from right to left. This is done to
 * faciliate decapsulation of packet header by simple shift/mask operations.
 *
 * For instance, an IPv6/TCP packet will be identified as :
 * [IPPROTO_NONE, IPPROTO_NONE, IPPROTO_TCP, IPPROTO_IPV6]
 *
 * We expect four elements to be sufficient for most uses, the max being
 * currently used by an hypothetical signed MAP-Me update :
 * [IPPROTO_ICMPRD, IPPROTO_AH, IPPROTO_ICMP, IPPROTO_IPV6]
 */

#define HICN_FORMAT_LEN 4

typedef union
{
  /** protocol layers representation */
  struct
  {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    u8 l1; /**< First layer */
    u8 l2; /**< Second layer */
    u8 l3; /**< Third layer */
    u8 l4; /**< Fourth layer */
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    u8 l4; /**< Fourth layer */
    u8 l3; /**< Third layer */
    u8 l2; /**< Second layer */
    u8 l1; /**< First layer */
#elif _WIN32 /* Windows is assumed little-endian */
    u8 l1;
    u8 l2;
    u8 l3;
    u8 l4;
#else
#error "Unsupported endianness"
#endif
  };
  /** u32 representation */
  u32 as_u32;
  u8 as_u8[HICN_FORMAT_LEN];
} hicn_packet_format_t;

/* Common protocol layers */
/* Common protocol layers */
#ifndef _WIN32
#define HICN_PACKET_FORMAT(x, y, z, t)                                        \
  (hicn_packet_format_t)                                                      \
  {                                                                           \
    {                                                                         \
      .l1 = x, .l2 = y, .l3 = z, .l4 = t                                      \
    }                                                                         \
  }
#else
inline const hicn_packet_format_t
HICN_PACKET_FORMAT (int x, int y, int z, int t)
{
  hicn_packet_format_t format;
  format.l1 = x;
  format.l2 = y;
  format.l3 = z;
  format.l4 = t;
  return format;
}
#endif

extern const char *const _protocol_str[];

#define protocol_str(x) protocol_str[x]

int hicn_packet_format_snprintf (char *s, size_t size,
				 hicn_packet_format_t format);

#define MAXSZ_HICN_PACKET_FORMAT 4 * 4 + 3 // ICMP/ICMP/ICMP/ICMP

#if !defined(__cplusplus)
#define constexpr const
#endif

static constexpr hicn_packet_format_t HICN_PACKET_FORMAT_IPV4_TCP =
  HICN_PACKET_FORMAT (IPPROTO_IP, IPPROTO_TCP, IPPROTO_NONE, IPPROTO_NONE);
static constexpr hicn_packet_format_t HICN_PACKET_FORMAT_IPV4_ICMP =
  HICN_PACKET_FORMAT (IPPROTO_IP, IPPROTO_ICMP, IPPROTO_NONE, IPPROTO_NONE);
static constexpr hicn_packet_format_t HICN_PACKET_FORMAT_IPV6_TCP =
  HICN_PACKET_FORMAT (IPPROTO_IPV6, IPPROTO_TCP, IPPROTO_NONE, IPPROTO_NONE);
static constexpr hicn_packet_format_t HICN_PACKET_FORMAT_IPV6_ICMP =
  HICN_PACKET_FORMAT (IPPROTO_IPV6, IPPROTO_ICMPV6, IPPROTO_NONE,
		      IPPROTO_NONE);
static constexpr hicn_packet_format_t HICN_PACKET_FORMAT_NEW =
  HICN_PACKET_FORMAT (IPPROTO_ENCAP, IPPROTO_NONE, IPPROTO_NONE, IPPROTO_NONE);
static constexpr hicn_packet_format_t HICN_PACKET_FORMAT_IPV4_UDP =
  HICN_PACKET_FORMAT (IPPROTO_IP, IPPROTO_UDP, IPPROTO_ENCAP, IPPROTO_NONE);
static constexpr hicn_packet_format_t HICN_PACKET_FORMAT_IPV6_UDP =
  HICN_PACKET_FORMAT (IPPROTO_IPV6, IPPROTO_UDP, IPPROTO_ENCAP, IPPROTO_NONE);
static constexpr hicn_packet_format_t HICN_PACKET_FORMAT_IPV4_TCP_AH =
  HICN_PACKET_FORMAT (IPPROTO_IP, IPPROTO_TCP, IPPROTO_AH, IPPROTO_NONE);
static constexpr hicn_packet_format_t HICN_PACKET_FORMAT_IPV4_ICMP_AH =
  HICN_PACKET_FORMAT (IPPROTO_IP, IPPROTO_ICMP, IPPROTO_AH, IPPROTO_NONE);
static constexpr hicn_packet_format_t HICN_PACKET_FORMAT_IPV6_TCP_AH =
  HICN_PACKET_FORMAT (IPPROTO_IPV6, IPPROTO_TCP, IPPROTO_AH, IPPROTO_NONE);
static constexpr hicn_packet_format_t HICN_PACKET_FORMAT_IPV6_ICMP_AH =
  HICN_PACKET_FORMAT (IPPROTO_IPV6, IPPROTO_ICMPV6, IPPROTO_AH, IPPROTO_NONE);
static constexpr hicn_packet_format_t HICN_PACKET_FORMAT_NEW_AH =
  HICN_PACKET_FORMAT (IPPROTO_ENCAP, IPPROTO_AH, IPPROTO_NONE, IPPROTO_NONE);
static constexpr hicn_packet_format_t HICN_PACKET_FORMAT_IPV6_UDP_AH =
  HICN_PACKET_FORMAT (IPPROTO_IPV6, IPPROTO_UDP, IPPROTO_ENCAP, IPPROTO_AH);
static constexpr hicn_packet_format_t HICN_PACKET_FORMAT_IPV4_UDP_AH =
  HICN_PACKET_FORMAT (IPPROTO_IP, IPPROTO_UDP, IPPROTO_ENCAP, IPPROTO_AH);
static constexpr hicn_packet_format_t HICN_PACKET_FORMAT_NONE =
  HICN_PACKET_FORMAT (IPPROTO_NONE, IPPROTO_NONE, IPPROTO_NONE, IPPROTO_NONE);

/**
 * @brief Return the hICN format with an additional AH header
 * @param [in] format - hICN packet format
 * @return Updated hICN packet format
 */
static inline hicn_packet_format_t
hicn_get_ah_format (hicn_packet_format_t format)
{
  hicn_packet_format_t ret = format;
  for (unsigned i = 0; i < HICN_FORMAT_LEN; i++)
    {
      switch (ret.as_u8[i])
	{
	case IPPROTO_AH:
	  return ret;
	case IPPROTO_NONE:
	  ret.as_u8[i] = IPPROTO_AH;
	  return ret;
	default:
	  break;
	}
    }
  return ret;
}

/*
 * MAX(IPV4_HDRLEN (20), IPV6_HDRLEN (40))
 *   + MAX (TCP_HDRLEN (20), UDP_HDRLEN (8), ICMP_HDRLEN (8),  NEW_HDRLEN (32))
 *   + AH_HDRLEN
 */
#define HICN_HDRLEN_MAX 72

/**
 * @brief Check if type is none.
 * @return 1 if none, 0 otherwise
 */
static inline int
hicn_type_is_none (hicn_packet_format_t format)
{
  return (format.l1 == IPPROTO_NONE) && (format.l2 == IPPROTO_NONE) &&
	 (format.l3 == IPPROTO_NONE) && (format.l4 == IPPROTO_NONE);
}

#define _is_ipv4(format) (format.l1 == IPPROTO_IP)
#define _is_ipv6(format) (format.l1 == IPPROTO_IPV6)
#define _is_tcp(format)	 (format.l2 == IPPROTO_TCP)
#define _is_udp(format)	 (format.l2 == IPPROTO_UDP)
#define _is_icmp(format)                                                      \
  ((format.l2 == IPPROTO_ICMP) || (format.l2 == IPPROTO_ICMPV6))
#define _is_cmpr(format) ((format & HFO_CMPR) >> 5)
#define _is_ah(format)                                                        \
  ((format.l1 == IPPROTO_AH) || (format.l2 == IPPROTO_AH) ||                  \
   (format.l3 == IPPROTO_AH))

/*
 * @brief hICN packet types
 *
 * probes are like normal interest & data but:
 *  - interests use BFD port as the destination
 *  - data use BFD port as the source + expiry time must be 0.
 * if any of these conditions is not met, the packet is still matched as an
 * interest or data packet.
 *
 */

#define foreach_packet_type                                                   \
  _ (UNDEFINED)                                                               \
  _ (INTEREST)                                                                \
  _ (DATA)                                                                    \
  _ (WLDR_NOTIFICATION)                                                       \
  _ (MAPME)                                                                   \
  _ (PROBE)                                                                   \
  _ (COMMAND)                                                                 \
  _ (N)

/**
 * @brief hICN Packet type
 */
typedef enum
{
#define _(x) HICN_PACKET_TYPE_##x,
  foreach_packet_type
#undef _
} hicn_packet_type_t;
#undef foreach_type

extern const char *_hicn_packet_type_str[];

#define hicn_packet_type_str(x) _hicn_packet_type_str[x]

/**
 * @brief hICN Payload type
 *
 * This type distinguishes several types of data packet, which can either carry
 * content data, or Manifest
 */
typedef enum
{
  HPT_DATA = 0,
  HPT_MANIFEST = 1,
  HPT_UNSPEC = 999
} hicn_payload_type_t;

/* Path label */

typedef u8 hicn_path_label_t;

#define INVALID_PATH_LABEL 0

/**
 * @brief Path label computations
 *
 * Path label is computed by accumulating the identifiers of successive output
 * faces as a Data packet is traveling from its producer back to the consumer
 * originating the Interest.
 *
 * NOTE: this computation is not (yet) part of the hICN specification.
 */

#define HICN_PATH_LABEL_MASK	  0x000000ff
#define HICN_PATH_LABEL_SIZE_BITS sizeof (hicn_path_label_t) * 8

/**
 * @brief Path label update
 * @param [in] current_label Current path_label
 * @param [in] face_id The face identifier to combine into the path label
 * @param [out] new_label Computed path_label
 *
 * This function updates the current_label based on the new face_id, and
 * returns
 */
static inline void
update_path_label (hicn_path_label_t current_label, hicn_faceid_t face_id,
		   hicn_path_label_t *new_label)
{
  hicn_path_label_t pl_face_id =
    (hicn_path_label_t) (face_id & HICN_PATH_LABEL_MASK);

  *new_label = ((current_label << 1) |
		(current_label >> (HICN_PATH_LABEL_SIZE_BITS - 1))) ^
	       pl_face_id;
}

/***************************************************************
 * Statistics
 ***************************************************************/

typedef struct
{
  // Packets processed
  uint32_t countReceived; // Interest and data only
  uint32_t countInterestsReceived;
  uint32_t countObjectsReceived;

  // Packets Dropped
  uint32_t countDropped;
  uint32_t countInterestsDropped;
  uint32_t countObjectsDropped;
  uint32_t countOtherDropped;

  // Forwarding
  uint32_t countInterestForwarded;
  uint32_t countObjectsForwarded;

  // Errors while forwarding
  uint32_t countDroppedConnectionNotFound;
  uint32_t countSendFailures;
  uint32_t countDroppedNoRoute;

  // Interest processing
  uint32_t countInterestsAggregated;
  uint32_t countInterestsRetransmitted;
  uint32_t countInterestsSatisfiedFromStore;
  uint32_t countInterestsExpired;

  // Data processing
  uint32_t countDroppedNoReversePath;
  uint32_t countDataExpired;

  // TODO(eloparco): Currently not used
  // uint32_t countDroppedNoHopLimit;
  // uint32_t countDroppedZeroHopLimitFromRemote;
  // uint32_t countDroppedZeroHopLimitToRemote;
} forwarder_stats_t;

typedef struct
{
  uint32_t n_pit_entries;
  uint32_t n_cs_entries;
  uint32_t n_lru_evictions;
} pkt_cache_stats_t;

typedef struct
{
  forwarder_stats_t forwarder;
  pkt_cache_stats_t pkt_cache;
} hicn_light_stats_t;

typedef struct
{
  struct
  {
    uint32_t rx_pkts;
    uint32_t rx_bytes;
    uint32_t tx_pkts;
    uint32_t tx_bytes;
  } interests;
  struct
  {
    uint32_t rx_pkts;
    uint32_t rx_bytes;
    uint32_t tx_pkts;
    uint32_t tx_bytes;
  } data;
} connection_stats_t;

#endif /* HICN_BASE_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
