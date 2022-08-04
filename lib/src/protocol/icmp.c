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

#include <hicn/error.h>
#include <string.h>

#include "icmp.h"
#include "../ops.h"

DECLARE_get_interest_locator (icmp, UNEXPECTED);
DECLARE_set_interest_locator (icmp, UNEXPECTED);
DECLARE_get_interest_name (icmp, UNEXPECTED);
DECLARE_set_interest_name (icmp, UNEXPECTED);
DECLARE_get_interest_name_suffix (icmp, UNEXPECTED);
DECLARE_set_interest_name_suffix (icmp, UNEXPECTED);
DECLARE_get_data_locator (icmp, UNEXPECTED);
DECLARE_set_data_locator (icmp, UNEXPECTED);
DECLARE_get_data_name (icmp, UNEXPECTED);
DECLARE_set_data_name (icmp, UNEXPECTED);
DECLARE_get_data_name_suffix (icmp, UNEXPECTED);
DECLARE_set_data_name_suffix (icmp, UNEXPECTED);
DECLARE_get_data_path_label (icmp, UNEXPECTED);
DECLARE_set_data_path_label (icmp, UNEXPECTED);
DECLARE_update_data_path_label (icmp, UNEXPECTED);
DECLARE_get_lifetime (icmp, UNEXPECTED);
DECLARE_set_lifetime (icmp, UNEXPECTED);
// DECLARE_get_payload_len (icmp, UNEXPECTED);
DECLARE_set_payload_len (icmp, UNEXPECTED);
DECLARE_get_payload_type (icmp, UNEXPECTED);
DECLARE_set_payload_type (icmp, UNEXPECTED);
DECLARE_get_signature (icmp, UNEXPECTED);
DECLARE_has_signature (icmp, UNEXPECTED);
DECLARE_is_last_data (icmp, UNEXPECTED);
DECLARE_set_last_data (icmp, UNEXPECTED);
DECLARE_get_ttl (icmp, UNEXPECTED);
DECLARE_set_ttl (icmp, UNEXPECTED);
DECLARE_get_src_port (icmp, UNEXPECTED);
DECLARE_set_src_port (icmp, UNEXPECTED);
DECLARE_get_dst_port (icmp, UNEXPECTED);
DECLARE_set_dst_port (icmp, UNEXPECTED);

int
icmp_init_packet_header (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  pkbuf->icmp = pkbuf->len;
  if (ICMP_HDRLEN > pkbuf->buffer_size - pkbuf->len)
    return -1;
  pkbuf->len += ICMP_HDRLEN;

  _icmp_header_t *icmp = pkbuf_get_icmp (pkbuf);

  *icmp = (_icmp_header_t){
    .type = 0,
    .code = 0,
    .csum = 0,
  };

  return CALL_CHILD (init_packet_header, pkbuf, pos);
}

int
icmp_reset_interest_for_hash (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  _icmp_header_t *icmp = pkbuf_get_icmp (pkbuf);

  icmp->csum = 0;

  return CALL_CHILD (reset_interest_for_hash, pkbuf, pos);
}

int
icmp_reset_data_for_hash (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  _icmp_header_t *icmp = pkbuf_get_icmp (pkbuf);

  icmp->csum = 0;

  return CALL_CHILD (reset_data_for_hash, pkbuf, pos);
}

int
icmp_update_checksums (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       u16 partial_csum, size_t payload_len)
{
  return HICN_LIB_ERROR_NOT_IMPLEMENTED;
  //    icmp->csum = 0;
  //    icmp->csum = csum(h->bytes, TCP_HDRLEN + payload_len,
  //    ~partial_csum);
  //
  //    return CALL_CHILD(update_checksums, pkbuf, pos->icmp, 0,
  //    payload_len);
}

int
icmp_update_checksums_incremental (const hicn_packet_buffer_t *pkbuf,
				   size_t pos, u16 *old_val, u16 *new_val,
				   u8 size, bool skip_first)
{
  return HICN_LIB_ERROR_NOT_IMPLEMENTED;
}

int
icmp_verify_checksums (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       u16 partial_csum, size_t payload_len)
{
  return HICN_LIB_ERROR_NOT_IMPLEMENTED;
  //    if (csum(h->bytes, TCP_HDRLEN + payload_len, ~partial_csum) != 0)
  //        return HICN_LIB_ERROR_CORRUPTED_PACKET;
  //    return CALL_CHILD(verify_checksums, pkbuf, pos->icmp, 0,
  //    payload_len);
}

int
icmp_rewrite_interest (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       const hicn_ip_address_t *addr_new,
		       hicn_ip_address_t *addr_old)
{
  return HICN_LIB_ERROR_NOT_IMPLEMENTED;
  //    u16 *icmp_checksum = &(icmp->csum);
  //
  //    /*
  //     * Padding fields are set to zero so we can apply checksum on the
  //     * whole struct by interpreting it as IPv6 in all cases
  //     *
  //     * v4 code would be:
  //     * csum = ip_csum_sub_even (*icmp_checksum, h->ipv4.saddr.as_u32);
  //     * csum = ip_csum_add_even (csum, h->ipv4.saddr.as_u32);
  //     */
  //    u16 csum = ip_csum_sub_even (*icmp_checksum, h->ipv6.saddr.as_u64[0]);
  //    csum = ip_csum_sub_even (csum, h->ipv6.saddr.as_u64[1]);
  //    csum = ip_csum_add_even (csum, h->ipv6.saddr.as_u64[0]);
  //    csum = ip_csum_add_even (csum, h->ipv6.saddr.as_u64[1]);
  //
  //    *icmp_checksum = ip_csum_fold (csum);
  //
  //    return HICN_LIB_ERROR_NONE;
}

int
icmp_rewrite_data (const hicn_packet_buffer_t *pkbuf, size_t pos,
		   const hicn_ip_address_t *addr_new,
		   hicn_ip_address_t *addr_old, const hicn_faceid_t face_id,
		   u8 reset_pl)
{
  return HICN_LIB_ERROR_NOT_IMPLEMENTED;
  //    u16 *icmp_checksum = &(icmp->csum);
  //
  //    /*
  //     * Padding fields are set to zero so we can apply checksum on the
  //     * whole struct by interpreting it as IPv6 in all cases
  //     *
  //     * v4 code would be:
  //     * csum = ip_csum_sub_even (*icmp_checksum, h->ipv4.saddr.as_u32);
  //     * csum = ip_csum_add_even (csum, h->ipv4.saddr.as_u32);
  //     */
  //    u16 csum = ip_csum_sub_even (*icmp_checksum, addr_old->ip6.as_u64[0]);
  //    csum = ip_csum_sub_even (*icmp_checksum, addr_old->ip6.as_u64[1]);
  //    csum = ip_csum_add_even (csum, addr_new->ip6.as_u64[0]);
  //    csum = ip_csum_add_even (csum, addr_new->ip6.as_u64[1]);
  //
  //    csum = ip_csum_sub_even (csum, icmp->path_label);
  //    icmp_update_data_path_label(pkbuf, pos, face_id);
  //    csum = ip_csum_add_even (csum, icmp->path_label);
  //
  //    *icmp_checksum = ip_csum_fold (csum);
  //
  //    return HICN_LIB_ERROR_NONE;
}

int
icmp_get_type (const hicn_packet_buffer_t *pkbuf, const size_t pos,
	       hicn_packet_type_t *type)
{
  return CALL_CHILD (get_type, pkbuf, pos, type);
}

int
icmp_set_type (const hicn_packet_buffer_t *pkbuf, size_t pos,
	       hicn_packet_type_t type)
{
  return CALL_CHILD (set_type, pkbuf, pos, type);
}

int
icmp_get_signature_size (const hicn_packet_buffer_t *pkbuf, size_t pos,
			 size_t *signature_size)
{
  return CALL_CHILD (get_signature_size, pkbuf, pos, signature_size);
}

int
icmp_set_signature_size (const hicn_packet_buffer_t *pkbuf, size_t pos,
			 size_t signature_size)
{
  return CALL_CHILD (set_signature_size, pkbuf, pos, signature_size);
}

int
icmp_set_signature_padding (const hicn_packet_buffer_t *pkbuf, size_t pos,
			    size_t padding)
{
  return CALL_CHILD (set_signature_padding, pkbuf, pos, padding);
}

int
icmp_get_signature_padding (const hicn_packet_buffer_t *pkbuf, size_t pos,
			    size_t *padding)
{
  return CALL_CHILD (get_signature_padding, pkbuf, pos, padding);
}

int
icmp_set_signature_timestamp (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      uint64_t signature_timestamp)
{
  return CALL_CHILD (set_signature_timestamp, pkbuf, pos, signature_timestamp);
}

int
icmp_get_signature_timestamp (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      uint64_t *signature_timestamp)
{
  return CALL_CHILD (get_signature_timestamp, pkbuf, pos, signature_timestamp);
}

int
icmp_set_validation_algorithm (const hicn_packet_buffer_t *pkbuf, size_t pos,
			       uint8_t validation_algorithm)
{
  return CALL_CHILD (set_validation_algorithm, pkbuf, pos,
		     validation_algorithm);
}

int
icmp_get_validation_algorithm (const hicn_packet_buffer_t *pkbuf, size_t pos,
			       uint8_t *validation_algorithm)
{
  return CALL_CHILD (get_validation_algorithm, pkbuf, pos,
		     validation_algorithm);
}

int
icmp_set_key_id (const hicn_packet_buffer_t *pkbuf, size_t pos,
		 uint8_t *key_id, size_t key_len)
{
  return CALL_CHILD (set_key_id, pkbuf, pos, key_id, key_len);
}

int
icmp_get_key_id (const hicn_packet_buffer_t *pkbuf, size_t pos,
		 uint8_t **key_id, uint8_t *key_id_size)
{
  return CALL_CHILD (get_key_id, pkbuf, pos, key_id, key_id_size);
}

DECLARE_HICN_OPS (icmp, ICMP_HDRLEN);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
