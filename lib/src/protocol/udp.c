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

#include <stdlib.h>
#include <string.h>
#include <hicn/common.h>
#include <hicn/error.h>
#include <hicn/ops.h>

#include <hicn/protocol/udp.h>

DECLARE_get_interest_locator (udp, UNEXPECTED);
DECLARE_set_interest_locator (udp, UNEXPECTED);
DECLARE_get_interest_name (udp, UNEXPECTED);
DECLARE_set_interest_name (udp, UNEXPECTED);
DECLARE_get_data_locator (udp, UNEXPECTED);
DECLARE_set_data_locator (udp, UNEXPECTED);
DECLARE_get_data_name (udp, UNEXPECTED);
DECLARE_set_data_name (udp, UNEXPECTED);
DECLARE_get_payload_length (udp, UNEXPECTED);
DECLARE_set_payload_length (udp, UNEXPECTED);

int
udp_init_packet_header (hicn_type_t type, hicn_protocol_t *h)
{
  size_t total_header_length;
  int rc = CHILD_OPS (get_header_length, type, h, &total_header_length);
  if (rc < 0)
    return rc;

  /* *INDENT-OFF* */
  h->udp = (_udp_header_t){ .src_port = 0,
			    .dst_port = 0,
			    .length = htons ((u16) total_header_length),
			    .checksum = 0 };
  /* *INDENT-ON* */
  return CHILD_OPS (init_packet_header, type, h);
}

int
udp_get_interest_name_suffix (hicn_type_t type, const hicn_protocol_t *h,
			      hicn_name_suffix_t *suffix)
{
  return CHILD_OPS (get_interest_name_suffix, type, h, suffix);
}

int
udp_set_interest_name_suffix (hicn_type_t type, hicn_protocol_t *h,
			      const hicn_name_suffix_t *suffix)
{
  return CHILD_OPS (set_interest_name_suffix, type, h, suffix);
}

int
udp_is_interest (hicn_type_t type, const hicn_protocol_t *h, int *is_interest)
{
  return CHILD_OPS (is_interest, type, h, is_interest);
}

int
udp_mark_packet_as_interest (hicn_type_t type, hicn_protocol_t *h)
{
  return CHILD_OPS (mark_packet_as_interest, type, h);
}

int
udp_mark_packet_as_data (hicn_type_t type, hicn_protocol_t *h)
{
  return CHILD_OPS (mark_packet_as_data, type, h);
}

int
udp_reset_interest_for_hash (hicn_type_t type, hicn_protocol_t *h)
{
  return CHILD_OPS (reset_interest_for_hash, type, h);
}

int
udp_get_data_name_suffix (hicn_type_t type, const hicn_protocol_t *h,
			  hicn_name_suffix_t *suffix)
{
  return CHILD_OPS (get_data_name_suffix, type, h, suffix);
}

int
udp_set_data_name_suffix (hicn_type_t type, hicn_protocol_t *h,
			  const hicn_name_suffix_t *suffix)
{
  return CHILD_OPS (set_data_name_suffix, type, h, suffix);
}

int
udp_get_data_pathlabel (hicn_type_t type, const hicn_protocol_t *h,
			u32 *pathlabel)
{
  return CHILD_OPS (get_data_pathlabel, type, h, pathlabel);
}

int
udp_set_data_pathlabel (hicn_type_t type, hicn_protocol_t *h,
			const u32 pathlabel)
{
  return CHILD_OPS (set_data_pathlabel, type, h, pathlabel);
}

int
udp_update_data_pathlabel (hicn_type_t type, hicn_protocol_t *h,
			   const hicn_faceid_t face_id)
{
  return CHILD_OPS (update_data_pathlabel, type, h, face_id);
}

int
udp_reset_data_for_hash (hicn_type_t type, hicn_protocol_t *h)
{
  return CHILD_OPS (reset_data_for_hash, type, h);
}

int
udp_get_lifetime (hicn_type_t type, const hicn_protocol_t *h,
		  hicn_lifetime_t *lifetime)
{
  return CHILD_OPS (get_lifetime, type, h, lifetime);
}

int
udp_set_lifetime (hicn_type_t type, hicn_protocol_t *h,
		  const hicn_lifetime_t lifetime)
{
  return CHILD_OPS (set_lifetime, type, h, lifetime);
}

int
udp_update_checksums (hicn_type_t type, hicn_protocol_t *h, u16 partial_csum,
		      size_t payload_length)
{
  return CHILD_OPS (update_checksums, type, h, partial_csum, payload_length);
}

int
udp_verify_checksums (hicn_type_t type, hicn_protocol_t *h, u16 partial_csum,
		      size_t payload_length)
{
  return CHILD_OPS (verify_checksums, type, h, partial_csum, payload_length);
}

int
udp_rewrite_interest (hicn_type_t type, hicn_protocol_t *h,
		      const ip_address_t *addr_new, ip_address_t *addr_old)
{
  return CHILD_OPS (rewrite_interest, type, h, addr_new, addr_old);
}

int
udp_rewrite_data (hicn_type_t type, hicn_protocol_t *h,
		  const ip_address_t *addr_new, ip_address_t *addr_old,
		  const hicn_faceid_t face_id, u8 reset_pl)
{
  return CHILD_OPS (rewrite_data, type, h, addr_new, addr_old, face_id,
		    reset_pl);
}

int
udp_get_length (hicn_type_t type, const hicn_protocol_t *h,
		size_t *header_length)
{
  *header_length = IPV6_HDRLEN + ntohs (h->ipv6.len);
  return HICN_LIB_ERROR_NONE;
}

int
udp_get_current_header_length (hicn_type_t type, const hicn_protocol_t *h,
			       size_t *header_length)
{
  *header_length = UDP_HDRLEN;
  return HICN_LIB_ERROR_NONE;
}

int
udp_get_header_length (hicn_type_t type, const hicn_protocol_t *h,
		       size_t *header_length)
{
  size_t child_header_length = 0;
  int rc = CHILD_OPS (get_header_length, type, h, &child_header_length);
  if (rc < 0)
    return rc;
  *header_length = UDP_HDRLEN + child_header_length;
  return HICN_LIB_ERROR_NONE;
}

int
udp_get_payload_type (hicn_type_t type, const hicn_protocol_t *h,
		      hicn_payload_type_t *payload_type)
{
  return CHILD_OPS (get_payload_type, type, h, payload_type);
}

int
udp_set_payload_type (hicn_type_t type, hicn_protocol_t *h,
		      hicn_payload_type_t payload_type)
{
  return CHILD_OPS (set_payload_type, type, h, payload_type);
}

int
udp_get_signature_size (hicn_type_t type, const hicn_protocol_t *h,
			size_t *signature_size)
{
  return CHILD_OPS (get_signature_size, type, h, signature_size);
}

int
udp_set_signature_size (hicn_type_t type, hicn_protocol_t *h,
			size_t signature_size)
{
  return CHILD_OPS (set_signature_size, type, h, signature_size);
}

int
udp_set_signature_padding (hicn_type_t type, hicn_protocol_t *h,
			   size_t padding)
{
  return CHILD_OPS (set_signature_padding, type, h, padding);
}

int
udp_get_signature_padding (hicn_type_t type, const hicn_protocol_t *h,
			   size_t *padding)
{
  return CHILD_OPS (get_signature_padding, type, h, padding);
}

int
udp_set_signature_timestamp (hicn_type_t type, hicn_protocol_t *h,
			     uint64_t signature_timestamp)
{
  return CHILD_OPS (set_signature_timestamp, type, h, signature_timestamp);
}

int
udp_get_signature_timestamp (hicn_type_t type, const hicn_protocol_t *h,
			     uint64_t *signature_timestamp)
{
  return CHILD_OPS (get_signature_timestamp, type, h, signature_timestamp);
}

int
udp_set_validation_algorithm (hicn_type_t type, hicn_protocol_t *h,
			      uint8_t validation_algorithm)
{
  return CHILD_OPS (set_validation_algorithm, type, h, validation_algorithm);
}

int
udp_get_validation_algorithm (hicn_type_t type, const hicn_protocol_t *h,
			      uint8_t *validation_algorithm)
{
  return CHILD_OPS (get_validation_algorithm, type, h, validation_algorithm);
}

int
udp_set_key_id (hicn_type_t type, hicn_protocol_t *h, uint8_t *key_id)
{
  return CHILD_OPS (set_key_id, type, h, key_id);
}

int
udp_get_key_id (hicn_type_t type, hicn_protocol_t *h, uint8_t **key_id,
		uint8_t *key_id_size)
{
  return CHILD_OPS (get_key_id, type, h, key_id, key_id_size);
}

int
udp_get_signature (hicn_type_t type, hicn_protocol_t *h, uint8_t **signature)
{
  return CHILD_OPS (get_signature, type, h, signature);
}

int
udp_is_last_data (hicn_type_t type, const hicn_protocol_t *h, int *is_last)
{
  return CHILD_OPS (is_last_data, type, h, is_last);
}

int
udp_set_last_data (hicn_type_t type, hicn_protocol_t *h)
{
  return CHILD_OPS (set_last_data, type, h);
}

DECLARE_HICN_OPS (udp);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
