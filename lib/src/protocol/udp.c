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

#include "udp.h"
#include "../ops.h"

DECLARE_get_interest_locator (udp, UNEXPECTED);
DECLARE_set_interest_locator (udp, UNEXPECTED);
DECLARE_get_interest_name (udp, UNEXPECTED);
DECLARE_set_interest_name (udp, UNEXPECTED);
DECLARE_get_data_locator (udp, UNEXPECTED);
DECLARE_set_data_locator (udp, UNEXPECTED);
DECLARE_get_data_name (udp, UNEXPECTED);
DECLARE_set_data_name (udp, UNEXPECTED);
DECLARE_set_payload_len (udp, UNEXPECTED);
DECLARE_get_ttl (udp, UNEXPECTED);
DECLARE_set_ttl (udp, UNEXPECTED);

int
udp_init_packet_header (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  pkbuf->udp = pkbuf->len;
  if (UDP_HDRLEN > pkbuf->buffer_size - pkbuf->len)
    return -1;
  pkbuf->len += UDP_HDRLEN;

  _udp_header_t *udp = pkbuf_get_udp (pkbuf);

  size_t len = hicn_packet_get_len (pkbuf) -
	       ((u8 *) udp - pkbuf_get_header (pkbuf)) -
	       sizeof (_udp_header_t);

  // clang-format off
  *udp = (_udp_header_t){
    .src_port = 0,
    .dst_port = 0,
    .len = htons ((u16) len),
    .checksum = 0
  };
  // clang-format on
  return CALL_CHILD (init_packet_header, pkbuf, pos);
}

int
udp_get_interest_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      hicn_name_suffix_t *suffix)
{
  return CALL_CHILD (get_interest_name_suffix, pkbuf, pos, suffix);
}

int
udp_set_interest_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      const hicn_name_suffix_t *suffix)
{
  return CALL_CHILD (set_interest_name_suffix, pkbuf, pos, suffix);
}

int
udp_get_type (const hicn_packet_buffer_t *pkbuf, const size_t pos,
	      hicn_packet_type_t *type)
{
  return CALL_CHILD (get_type, pkbuf, pos, type);
}

int
udp_set_type (const hicn_packet_buffer_t *pkbuf, size_t pos,
	      hicn_packet_type_t type)
{
  return CALL_CHILD (set_type, pkbuf, pos, type);
}

int
udp_reset_interest_for_hash (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  return CALL_CHILD (reset_interest_for_hash, pkbuf, pos);
}

int
udp_get_data_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			  hicn_name_suffix_t *suffix)
{
  return CALL_CHILD (get_data_name_suffix, pkbuf, pos, suffix);
}

int
udp_set_data_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			  const hicn_name_suffix_t *suffix)
{
  return CALL_CHILD (set_data_name_suffix, pkbuf, pos, suffix);
}

int
udp_get_data_path_label (const hicn_packet_buffer_t *pkbuf, size_t pos,
			 hicn_path_label_t *path_label)
{
  return CALL_CHILD (get_data_path_label, pkbuf, pos, path_label);
}

int
udp_set_data_path_label (const hicn_packet_buffer_t *pkbuf, size_t pos,
			 hicn_path_label_t path_label)
{
  return CALL_CHILD (set_data_path_label, pkbuf, pos, path_label);
}

int
udp_update_data_path_label (const hicn_packet_buffer_t *pkbuf, size_t pos,
			    const hicn_faceid_t face_id)
{
  return CALL_CHILD (update_data_path_label, pkbuf, pos, face_id);
}

int
udp_reset_data_for_hash (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  return CALL_CHILD (reset_data_for_hash, pkbuf, pos);
}

int
udp_get_lifetime (const hicn_packet_buffer_t *pkbuf, size_t pos,
		  hicn_lifetime_t *lifetime)
{
  return CALL_CHILD (get_lifetime, pkbuf, pos, lifetime);
}

int
udp_set_lifetime (const hicn_packet_buffer_t *pkbuf, size_t pos,
		  const hicn_lifetime_t lifetime)
{
  return CALL_CHILD (set_lifetime, pkbuf, pos, lifetime);
}

int
udp_update_checksums (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      u16 partial_csum, size_t payload_len)
{
  return CALL_CHILD (update_checksums, pkbuf, pos, partial_csum, payload_len);
}

int
udp_update_checksums_incremental (const hicn_packet_buffer_t *pkbuf,
				  size_t pos, u16 *old_val, u16 *new_val,
				  u8 size, bool skip_first)
{
  return CALL_CHILD (update_checksums_incremental, pkbuf, pos, old_val,
		     new_val, size, false);
}

int
udp_verify_checksums (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      u16 partial_csum, size_t payload_len)
{
  return CALL_CHILD (verify_checksums, pkbuf, pos, partial_csum, payload_len);
}

int
udp_rewrite_interest (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      const hicn_ip_address_t *addr_new,
		      hicn_ip_address_t *addr_old)
{
  return CALL_CHILD (rewrite_interest, pkbuf, pos, addr_new, addr_old);
}

int
udp_rewrite_data (const hicn_packet_buffer_t *pkbuf, size_t pos,
		  const hicn_ip_address_t *addr_new,
		  hicn_ip_address_t *addr_old, const hicn_faceid_t face_id,
		  u8 reset_pl)
{
  return CALL_CHILD (rewrite_data, pkbuf, pos, addr_new, addr_old, face_id,
		     reset_pl);
}

int
udp_get_payload_type (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      hicn_payload_type_t *payload_type)
{
  return CALL_CHILD (get_payload_type, pkbuf, pos, payload_type);
}

int
udp_set_payload_type (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      hicn_payload_type_t payload_type)
{
  return CALL_CHILD (set_payload_type, pkbuf, pos, payload_type);
}

int
udp_get_signature_size (const hicn_packet_buffer_t *pkbuf, size_t pos,
			size_t *signature_size)
{
  return CALL_CHILD (get_signature_size, pkbuf, pos, signature_size);
}

int
udp_set_signature_size (const hicn_packet_buffer_t *pkbuf, size_t pos,
			size_t signature_size)
{
  return CALL_CHILD (set_signature_size, pkbuf, pos, signature_size);
}

int
udp_has_signature (const hicn_packet_buffer_t *pkbuf, size_t pos, bool *flag)
{
  return CALL_CHILD (has_signature, pkbuf, pos, flag);
}

int
udp_set_signature_padding (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   size_t padding)
{
  return CALL_CHILD (set_signature_padding, pkbuf, pos, padding);
}

int
udp_get_signature_padding (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   size_t *padding)
{
  return CALL_CHILD (get_signature_padding, pkbuf, pos, padding);
}

int
udp_set_signature_timestamp (const hicn_packet_buffer_t *pkbuf, size_t pos,
			     uint64_t signature_timestamp)
{
  return CALL_CHILD (set_signature_timestamp, pkbuf, pos, signature_timestamp);
}

int
udp_get_signature_timestamp (const hicn_packet_buffer_t *pkbuf, size_t pos,
			     uint64_t *signature_timestamp)
{
  return CALL_CHILD (get_signature_timestamp, pkbuf, pos, signature_timestamp);
}

int
udp_set_validation_algorithm (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      uint8_t validation_algorithm)
{
  return CALL_CHILD (set_validation_algorithm, pkbuf, pos,
		     validation_algorithm);
}

int
udp_get_validation_algorithm (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      uint8_t *validation_algorithm)
{
  return CALL_CHILD (get_validation_algorithm, pkbuf, pos,
		     validation_algorithm);
}

int
udp_set_key_id (const hicn_packet_buffer_t *pkbuf, size_t pos, uint8_t *key_id,
		size_t key_len)
{
  return CALL_CHILD (set_key_id, pkbuf, pos, key_id, key_len);
}

int
udp_get_key_id (const hicn_packet_buffer_t *pkbuf, size_t pos,
		uint8_t **key_id, uint8_t *key_id_size)
{
  return CALL_CHILD (get_key_id, pkbuf, pos, key_id, key_id_size);
}

int
udp_get_signature (const hicn_packet_buffer_t *pkbuf, size_t pos,
		   uint8_t **signature)
{
  return CALL_CHILD (get_signature, pkbuf, pos, signature);
}

int
udp_is_last_data (const hicn_packet_buffer_t *pkbuf, size_t pos, int *is_last)
{
  return CALL_CHILD (is_last_data, pkbuf, pos, is_last);
}

int
udp_set_last_data (const hicn_packet_buffer_t *pkbuf, size_t pos)
{
  return CALL_CHILD (set_last_data, pkbuf, pos);
}

int
udp_get_src_port (const hicn_packet_buffer_t *pkbuf, size_t pos, u16 *port)
{
  _udp_header_t *udp = pkbuf_get_udp (pkbuf);

  *port = udp->src_port;
  return HICN_LIB_ERROR_NONE;
}

int
udp_set_src_port (const hicn_packet_buffer_t *pkbuf, size_t pos, u16 port)
{
  _udp_header_t *udp = pkbuf_get_udp (pkbuf);

  udp->src_port = port;
  return HICN_LIB_ERROR_NONE;
}

int
udp_get_dst_port (const hicn_packet_buffer_t *pkbuf, size_t pos, u16 *port)
{
  _udp_header_t *udp = pkbuf_get_udp (pkbuf);

  *port = udp->dst_port;
  return HICN_LIB_ERROR_NONE;
}

int
udp_set_dst_port (const hicn_packet_buffer_t *pkbuf, size_t pos, u16 port)
{
  _udp_header_t *udp = pkbuf_get_udp (pkbuf);

  udp->dst_port = port;
  return HICN_LIB_ERROR_NONE;
}

DECLARE_HICN_OPS (udp, UDP_HDRLEN);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
