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
 * @file header.h
 * @brief hICN header data structures.
 *
 * NOTE: These structures are used as convenient facade for accessing
 * the encapsulated headers. They are not written taking compiler padding
 * into account, then a sizeof() on these struct could not give the expected
 * result. For accessing the size of the hicn headers use the macros at the end
 * of this file.
 */

#ifndef HICN_HEADER_H
#define HICN_HEADER_H

#include "common.h"
#include "protocol.h"

typedef struct
{
  _ipv6_header_t ip;
  union
  {
    _tcp_header_t tcp;
    struct
    {
      _udp_header_t udp;
      _new_header_t newhdr;
    };
    _icmp_header_t icmp;
    _icmp_wldr_header_t wldr;
  };
} hicn_v6_hdr_t;

typedef struct
{
  _ipv6_header_t ip;
  union
  {
    struct
    {
      _tcp_header_t tcp;
      _ah_header_t ah;
    };
    struct
    {
      _udp_header_t udp;
      _new_header_t newhdr;
      _ah_header_t udp_ah;
    };
    struct
    {
      _icmp_header_t icmp;
      _ah_header_t icmp_ah;
    };
  };
} hicn_v6ah_hdr_t;

// For ipv4 we need to use packed structs as fields may be aligned to 64 bits
// (So for instance tcp header may start at byte #24 instead of byte 20)
typedef PACKED (struct {
  _ipv4_header_t ip;
  union
  {
    _tcp_header_t tcp;
    struct
    {
      _udp_header_t udp;
      _new_header_t newhdr;
    };
    _icmp_header_t icmp;
    _icmp_wldr_header_t wldr;
  };
}) hicn_v4_hdr_t;

typedef PACKED (struct {
  _ipv4_header_t ip;
  union
  {
    struct
    {
      _tcp_header_t tcp;
      _ah_header_t ah;
    };
    struct
    {
      _udp_header_t udp;
      _new_header_t newhdr;
      _ah_header_t udp_ah;
    };
    struct
    {
      _icmp_header_t icmp;
      _ah_header_t icmp_ah;
    };
  };
}) hicn_v4ah_hdr_t;

typedef union
{
  /* To deprecate as redundant with hicn_type_t */
  hicn_v6_hdr_t v6;
  hicn_v6ah_hdr_t v6ah;
  hicn_v4_hdr_t v4;
  hicn_v4ah_hdr_t v4ah;

  hicn_protocol_t protocol;
} hicn_header_t;

#define HICN_V6_TCP_HDRLEN  (IPV6_HDRLEN + TCP_HDRLEN)
#define HICN_V6_ICMP_HDRLEN (IPV6_HDRLEN + ICMP_HDRLEN)
#define HICN_V6_WLDR_HDRLEN (IPV6_HDRLEN + ICMPWLDR_HDRLEN)

#define HICN_V6_TCP_AH_HDRLEN  (HICN_V6_TCP_HDRLEN + AH_HDRLEN)
#define HICN_V6_ICMP_AH_HDRLEN (HICN_V6_ICMP_HDRLEN + AH_HDRLEN)

#define HICN_V4_TCP_HDRLEN  (IPV4_HDRLEN + TCP_HDRLEN)
#define HICN_V4_ICMP_HDRLEN (IPV4_HDRLEN + ICMP_HDRLEN)
#define HICN_V4_WLDR_HDRLEN (IPV4_HDRLEN + ICMPWLDR_HDRLEN)

#define HICN_V4_TCP_AH_HDRLEN  (HICN_V4_TCP_HDRLEN + AH_HDRLEN)
#define HICN_V4_ICMP_AH_HDRLEN (HICN_V4_ICMP_HDRLEN + AH_HDRLEN)

#define HICN_DEFAULT_PORT 9695

#endif /* HICN_HEADER_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
