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
 * @file header.h
 * @brief hICN header data structures.
 * details.
 */
#ifndef HICN_HEADER_H
#define HICN_HEADER_H

#include "common.h"
#include "protocol.h"

typedef struct {
  _ipv6_header_t ip;
  union {
    _tcp_header_t tcp;
    _icmp_header_t icmp;
    _icmp_wldr_header_t wldr;
  };
} hicn_v6_hdr_t;

typedef struct {
  _ipv6_header_t ip;
  union {
    struct {
      _tcp_header_t tcp;
      _ah_header_t ah;
    };
    struct {
      _icmp_header_t icmp;
      _ah_header_t icmp_ah;
    };
  };
} hicn_v6ah_hdr_t;

typedef struct {
  _ipv4_header_t ip;
  union {
    _tcp_header_t tcp;
    _icmp_header_t icmp;
    _icmp_wldr_header_t wldr;
  };
} hicn_v4_hdr_t;

typedef struct {
  _ipv4_header_t ip;
  union {
    struct {
      _tcp_header_t tcp;
      _ah_header_t ah;
    };
    struct {
      _icmp_header_t icmp;
      _ah_header_t icmp_ah;
    };
  };
} hicn_v4ah_hdr_t;

typedef union {
  /* To deprecate as redundant with hicn_type_t */
  hicn_v6_hdr_t v6;
  hicn_v6ah_hdr_t v6ah;
  hicn_v4_hdr_t v4;
  hicn_v4ah_hdr_t v4ah;

  hicn_protocol_t protocol;
} hicn_header_t;

#endif /* HICN_HEADER_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
