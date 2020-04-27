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
 * @file base.h
 * @brief Base hICN definitions.
 */

#ifndef HICN_BASE_H
#define HICN_BASE_H

#include "common.h"

/* Default header fields */
#define HICN_DEFAULT_TTL 254

typedef u32 hicn_faceid_t;
typedef u32 hicn_pathlabel_t;
typedef u32 hicn_lifetime_t;

#define HICN_MAX_LIFETIME_SCALED 0xFFFF
#define HICN_MAX_LIFETIME_MULTIPLIER 0x0F	/* 4 bits */
#define HICN_MAX_LIFETIME HICN_MAX_LIFETIME_SCALED << HICN_MAX_LIFETIME_MULTIPLIER

/**
 * @brief hICN packet format type
 *
 * The hICN type represents the sequence of protocols that we can find in packet
 * headers. They are represented as a quartet of u8 values, correponding to
 * IANA protocol assignment, and read from right to left. This is done to
 * faciliate decapsulation of packet header by simple shift/mask operations.
 *
 * For instance, an IPv6/TCP packet will be identified as :
 * [IPPROTO_NONE, IPPROTO_NONE, IPPROTO_TCP, IPPROTO_IPV6]
 *
 * We expect four elements to be sufficient for most uses, the max being
 * currently used by an hypothetical signed MAP-Me update :
 * [IPPROTO_ICMPRD, IPPROTO_AH, IPPROTO_ICMP, IPPROTO_IPV6]
 */
typedef union
{
    /** protocol layers representation */
  struct
  {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    u8 l1;     /**< First layer */
    u8 l2;     /**< Second layer */
    u8 l3;     /**< Third layer */
    u8 l4;     /**< Fourth layer */
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    u8 l4;     /**< Fourth layer */
    u8 l3;     /**< Third layer */
    u8 l2;     /**< Second layer */
    u8 l1;     /**< First layer */
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
} hicn_type_t;

/* Common protocol layers */
/* Common protocol layers */
#ifndef _WIN32
#define HICN_TYPE(x,y,z,t) (hicn_type_t) {{ .l1 = x, .l2 = y, .l3 = z, .l4 = t }}
#else
inline hicn_type_t
HICN_TYPE(int x, int y, int z, int t)
{
    hicn_type_t type;
    type.l1 = x;
    type.l2 = y;
    type.l3 = z;
    type.l4 = t;
    return type;
}
#endif

#define HICN_TYPE_IPV4_TCP     HICN_TYPE(IPPROTO_IP,   IPPROTO_TCP,    IPPROTO_NONE, IPPROTO_NONE)
#define HICN_TYPE_IPV4_UDP     HICN_TYPE(IPPROTO_IP,   IPPROTO_UDP,    IPPROTO_NONE, IPPROTO_NONE)
#define HICN_TYPE_IPV4_ICMP    HICN_TYPE(IPPROTO_IP,   IPPROTO_ICMP,   IPPROTO_NONE, IPPROTO_NONE)
#define HICN_TYPE_IPV6_TCP     HICN_TYPE(IPPROTO_IPV6, IPPROTO_TCP,    IPPROTO_NONE, IPPROTO_NONE)
#define HICN_TYPE_IPV6_UDP     HICN_TYPE(IPPROTO_IPV6, IPPROTO_UDP,    IPPROTO_NONE, IPPROTO_NONE)
#define HICN_TYPE_IPV6_ICMP    HICN_TYPE(IPPROTO_IPV6, IPPROTO_ICMPV6, IPPROTO_NONE, IPPROTO_NONE)
#define HICN_TYPE_IPV4_TCP_AH  HICN_TYPE(IPPROTO_IP,   IPPROTO_TCP,    IPPROTO_NONE, IPPROTO_NONE)
#define HICN_TYPE_IPV4_UDP_AH  HICN_TYPE(IPPROTO_IP,   IPPROTO_UDP,    IPPROTO_NONE, IPPROTO_NONE)
#define HICN_TYPE_IPV4_ICMP_AH HICN_TYPE(IPPROTO_IP,   IPPROTO_ICMP,   IPPROTO_NONE, IPPROTO_NONE)
#define HICN_TYPE_IPV6_TCP_AH  HICN_TYPE(IPPROTO_IPV6, IPPROTO_TCP,    IPPROTO_AH,   IPPROTO_NONE)
#define HICN_TYPE_IPV6_UDP_AH  HICN_TYPE(IPPROTO_IPV6, IPPROTO_UDP,    IPPROTO_AH,   IPPROTO_NONE)
#define HICN_TYPE_IPV6_ICMP_AH HICN_TYPE(IPPROTO_IPV6, IPPROTO_ICMPV6, IPPROTO_AH,   IPPROTO_NONE)
#define HICN_TYPE_NONE         HICN_TYPE(IPPROTO_NONE, IPPROTO_NONE,   IPPROTO_NONE, IPPROTO_NONE)

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

/**
 * @brief Path label computations
 *
 * Path label is computed by accumulating the identifiers of successive output
 * faces as a Data packet is traveling from its producer back to the consumer
 * originating the Interest.
 *
 * NOTE: this computation is not (yet) part of the hICN specification.
 */

// XXX TODO deprecate TODO XXX
#define HICN_PATH_LABEL_MASK 0xF000	/* 1000 0000 0000 0000 */
#define HICN_PATH_LABEL_SIZE 8 /* XXX in bits ? */

/**
 * @brief Path label update
 * @param [in] current_label Current pathlabel
 * @param [in] face_id The face identifier to combine into the path label
 * @param [out] new_label Computed pathlabel
 *
 * This function updates the current_label based on the new face_id, and returns
 */
always_inline void
update_pathlabel (hicn_pathlabel_t current_label, hicn_faceid_t face_id,
		  hicn_pathlabel_t * new_label)
{
  hicn_pathlabel_t pl_face_id =
    (hicn_pathlabel_t) ((face_id & HICN_PATH_LABEL_MASK) >>
			(16 - HICN_PATH_LABEL_SIZE));
  *new_label =
    ((current_label << 1) | (current_label >> (HICN_PATH_LABEL_SIZE - 1))) ^
    pl_face_id;
}

#endif /* HICN_BASE_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
