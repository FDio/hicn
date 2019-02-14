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

#ifndef __HICN_PARAM_H__
#define __HICN_PARAM_H__

/*
 * Features
 */
#define HICN_FEATURE_CS 1	//1 enable 0 disable

/*
 * Face compile-time parameters
 */
#define HICN_PARAM_FACES_MAX 512

STATIC_ASSERT ((HICN_PARAM_FACES_MAX & (HICN_PARAM_FACES_MAX - 1)) == 0,
	       "HICN_PARAM_FACES_MAX must be a power of 2");

/*
 * Max length for hICN names
 */
#define HICN_PARAM_HICN_NAME_LEN_MAX 20	//bytes

// Max next - hops supported in a FIB entry
#define HICN_PARAM_FIB_ENTRY_NHOPS_MAX   5

// Default and limit on weight, whatever weight means
#define HICN_PARAM_FIB_ENTRY_NHOP_WGHT_DFLT   0x10
#define HICN_PARAM_FIB_ENTRY_NHOP_WGHT_MAX    0xff

/*
 * PIT compile-time parameters
 */
#define HICN_PARAM_PIT_ENTRIES_MIN    1024
#define HICN_PARAM_PIT_ENTRIES_DFLT    1024 * 128
#define HICN_PARAM_PIT_ENTRIES_MAX      2 * 1024 * 1024

// aggregation limit(interest previous hops)
// Supported up to 516. For more than 4 faces this param must
// satisfy the equation (HICN_PARAM_PIT_ENTRY_PHOPS_MAX - 4) % 2 = 0
#define HICN_PARAM_PIT_ENTRY_PHOPS_MAX 20

STATIC_ASSERT ((HICN_PARAM_PIT_ENTRY_PHOPS_MAX <= HICN_PARAM_FACES_MAX),
	       "HICN_PARAM_PIT_ENTRY_PHOP_MAX must be <= than HICN_PARAM_FACES_MAX");

// PIT lifetime limits on API override this(in mseconds, integer type)
#define HICN_PARAM_PIT_LIFETIME_BOUND_MIN_SEC   100
#define HICN_PARAM_PIT_LIFETIME_BOUND_MAX_SEC  20000

//PIT lifetime params if not set at API(in mseconds, integer type)
#define HICN_PARAM_PIT_LIFETIME_DFLT_MIN_MS  200
#define HICN_PARAM_PIT_LIFETIME_DFLT_DFLT_MS 20000
#define HICN_PARAM_PIT_LIFETIME_DFLT_MAX_MS  20000

// Face CS reservation params
#define HICN_PARAM_FACE_MAX_CS_RESERVED 10000	//packets
#define HICN_PARAM_FACE_MIN_CS_RESERVED 0	//packets
#define HICN_PARAM_FACE_DFT_CS_RESERVED 1000	//packets

/*
 * CS compile-time parameters
 */
#define HICN_PARAM_CS_ENTRIES_MIN       0	// can disable CS
#define HICN_PARAM_CS_ENTRIES_DFLT      4 * 1024
#define HICN_PARAM_CS_ENTRIES_MAX       1024 * 1024

#define HICN_PARAM_CS_LRU_DEFAULT    (16 * 1024)

/* CS lifetime defines, in mseconds, integer type */
#define HICN_PARAM_CS_LIFETIME_MIN      100
#define HICN_PARAM_CS_LIFETIME_DFLT    (5 * 60 * 1000)	// 300 seconds
#define HICN_PARAM_CS_LIFETIME_MAX      (24 * 3600 * 1000)	//24 hours...

/* CS reserved portion for applications */
#define HICN_PARAM_CS_RESERVED_APP 30	//%

/* Cloning parameters */
/* ip4 */
#define HICN_IP4_VERSION_HEADER_LENGTH 0x45
#define HICN_IP4_PROTOCOL IP_PROTOCOL_TCP
#define HICN_IP4_TTL_DEFAULT 128

/* ip6 */
#define IPV6_DEFAULT_VERSION         6
#define IPV6_DEFAULT_TRAFFIC_CLASS   0
#define IPV6_DEFAULT_FLOW_LABEL      0
#define HCIN_IP6_VERSION_TRAFFIC_FLOW (IPV6_DEFAULT_VERSION << 28) |    \
  (IPV6_DEFAULT_TRAFFIC_CLASS << 20) |                                  \
  (IPV6_DEFAULT_FLOW_LABEL & 0xfffff)
#define HICN_IP6_PROTOCOL IP_PROTOCOL_TCP
#define HICN_IP6_HOP_LIMIT 0x40

#endif /* // __HICN_PARAM_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
