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
 * @file ops.c
 * @brief Initializers for protocol-independent packet operations
 */

#ifndef _WIN32
#include <netinet/in.h>
#endif
#include <stdlib.h>

#include "ops.h"
#include "protocol.h"

extern const hicn_ops_t hicn_ops_ipv4;
extern const hicn_ops_t hicn_ops_icmp;
extern const hicn_ops_t hicn_ops_udp;
extern const hicn_ops_t hicn_ops_tcp;
extern const hicn_ops_t hicn_ops_ipv6;
extern const hicn_ops_t hicn_ops_new;
extern const hicn_ops_t hicn_ops_ah;

/* Declare empty operations (terminates recursion on protocol layers) */

int
none_init_packet_header (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  pkbuf->payload = pkbuf->len;
  return HICN_LIB_ERROR_NONE;
}

DECLARE_get_interest_locator (none, NONE);
DECLARE_set_interest_locator (none, NONE);
DECLARE_get_interest_name (none, NONE);
DECLARE_set_interest_name (none, NONE);
DECLARE_get_interest_name_suffix (none, NONE);
DECLARE_set_interest_name_suffix (none, NONE);
DECLARE_get_type (none, NONE);
DECLARE_set_type (none, NONE);
DECLARE_reset_interest_for_hash (none, NONE);
DECLARE_get_data_locator (none, NONE);
DECLARE_set_data_locator (none, NONE);
DECLARE_get_data_name (none, NONE);
DECLARE_set_data_name (none, NONE);
DECLARE_get_data_name_suffix (none, NONE);
DECLARE_set_data_name_suffix (none, NONE);
DECLARE_get_data_path_label (none, NONE);
DECLARE_set_data_path_label (none, NONE);
DECLARE_update_data_path_label (none, NONE);
DECLARE_reset_data_for_hash (none, NONE);
DECLARE_get_lifetime (none, NONE);
DECLARE_set_lifetime (none, NONE);
DECLARE_update_checksums (none, NONE);
DECLARE_update_checksums_incremental (none, NONE);
DECLARE_verify_checksums (none, NONE);
DECLARE_rewrite_interest (none, NONE);
DECLARE_rewrite_data (none, NONE);
DECLARE_set_payload_len (none, NONE);
DECLARE_get_payload_type (none, NONE);
DECLARE_set_payload_type (none, NONE);
DECLARE_get_signature_size (none, NONE);
DECLARE_set_signature_size (none, NONE);
DECLARE_set_signature_timestamp (none, NONE);
DECLARE_get_signature_timestamp (none, NONE);
DECLARE_set_validation_algorithm (none, NONE);
DECLARE_get_validation_algorithm (none, NONE);
DECLARE_set_key_id (none, NONE);
DECLARE_get_key_id (none, NONE);
DECLARE_get_signature (none, NONE);
DECLARE_has_signature (none, NONE);
DECLARE_get_signature_padding (none, NONE);
DECLARE_set_signature_padding (none, NONE);
DECLARE_is_last_data (none, NONE);
DECLARE_set_last_data (none, NONE);
DECLARE_HICN_OPS (none, 0);

/**
 * @brief Virtual function table for packet operations
 * NOTE: protocol numbers have to be kept in order
 */
const hicn_ops_t *const hicn_ops_vft[] = {
  /*  0 */ [IPPROTO_IP] = &hicn_ops_ipv4,
  /*  1 */[IPPROTO_ICMP] = &hicn_ops_icmp,
  /*  6 */[IPPROTO_TCP] = &hicn_ops_tcp,
  /*  6 */[IPPROTO_UDP] = &hicn_ops_udp,
  /* 41 */[IPPROTO_IPV6] = &hicn_ops_ipv6,
  /* 51 */[IPPROTO_AH] = &hicn_ops_ah,
  /* 58 */[IPPROTO_ICMPV6] = &hicn_ops_icmp,
  /* 59 */[IPPROTO_NONE] = &hicn_ops_none,
  /* 98 */[IPPROTO_ENCAP] = &hicn_ops_new,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
