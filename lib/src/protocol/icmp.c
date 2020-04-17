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

#include <string.h>
#include <hicn/protocol/icmp.h>

#include <hicn/error.h>
#include <hicn/ops.h>

DECLARE_get_interest_locator (icmp, UNEXPECTED)
DECLARE_set_interest_locator (icmp, UNEXPECTED)
DECLARE_get_interest_name (icmp, UNEXPECTED)
DECLARE_set_interest_name (icmp, UNEXPECTED)
DECLARE_get_interest_name_suffix (icmp, UNEXPECTED)
DECLARE_set_interest_name_suffix (icmp, UNEXPECTED)
DECLARE_mark_packet_as_interest (icmp, UNEXPECTED)
DECLARE_mark_packet_as_data (icmp, UNEXPECTED)
DECLARE_get_data_locator (icmp, UNEXPECTED)
DECLARE_set_data_locator (icmp, UNEXPECTED)
DECLARE_get_data_name (icmp, UNEXPECTED)
DECLARE_set_data_name (icmp, UNEXPECTED)
DECLARE_get_data_name_suffix (icmp, UNEXPECTED)
DECLARE_set_data_name_suffix (icmp, UNEXPECTED)
DECLARE_get_data_pathlabel (icmp, UNEXPECTED)
DECLARE_set_data_pathlabel (icmp, UNEXPECTED)
DECLARE_update_data_pathlabel (icmp, UNEXPECTED)
DECLARE_get_lifetime (icmp, UNEXPECTED)
DECLARE_set_lifetime (icmp, UNEXPECTED)
DECLARE_get_length (icmp, UNEXPECTED)
DECLARE_get_payload_length (icmp, UNEXPECTED)
DECLARE_set_payload_length (icmp, UNEXPECTED)
DECLARE_get_signature (icmp, UNEXPECTED)

int icmp_init_packet_header (hicn_type_t type, hicn_protocol_t * h)
{
  h->icmp = (_icmp_header_t)
  {
  .type = 0,.code = 0,.csum = 0,};

  return HICN_LIB_ERROR_NONE;	// CHILD_OPS(init_packet_header, type, h->icmp);
}

int
icmp_reset_interest_for_hash (hicn_type_t type, hicn_protocol_t * h)
{
  h->icmp.csum = 0;

  return CHILD_OPS (reset_interest_for_hash, type, h);
}

int
icmp_reset_data_for_hash (hicn_type_t type, hicn_protocol_t * h)
{
  h->icmp.csum = 0;

  return CHILD_OPS (reset_data_for_hash, type, h);
}

int
icmp_update_checksums (hicn_type_t type, hicn_protocol_t * h,
		       u16 partial_csum, size_t payload_length)
{
  return HICN_LIB_ERROR_NOT_IMPLEMENTED;
//    h->icmp.csum = 0;
//    h->icmp.csum = csum(h->bytes, TCP_HDRLEN + payload_length, ~partial_csum);
//
//    return CHILD_OPS(update_checksums, type, h->icmp, 0, payload_length);
}

int
icmp_verify_checksums (hicn_type_t type, hicn_protocol_t * h,
		       u16 partial_csum, size_t payload_length)
{
  return HICN_LIB_ERROR_NOT_IMPLEMENTED;
//    if (csum(h->bytes, TCP_HDRLEN + payload_length, ~partial_csum) != 0)
//        return HICN_LIB_ERROR_CORRUPTED_PACKET;
//    return CHILD_OPS(verify_checksums, type, h->icmp, 0, payload_length);
}

int
icmp_rewrite_interest (hicn_type_t type, hicn_protocol_t * h,
		       const ip46_address_t * addr_new,
		       ip46_address_t * addr_old)
{
  return HICN_LIB_ERROR_NOT_IMPLEMENTED;
//    u16 *icmp_checksum = &(h->icmp.csum);
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
icmp_rewrite_data (hicn_type_t type, hicn_protocol_t * h,
		   const ip46_address_t * addr_new, ip46_address_t * addr_old,
		   const hicn_faceid_t face_id)
{
  return HICN_LIB_ERROR_NOT_IMPLEMENTED;
//    u16 *icmp_checksum = &(h->icmp.csum);
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
//    csum = ip_csum_sub_even (csum, h->icmp.pathlabel);
//    icmp_update_data_pathlabel(type, h, face_id);
//    csum = ip_csum_add_even (csum, h->icmp.pathlabel);
//
//    *icmp_checksum = ip_csum_fold (csum);
//
//    return HICN_LIB_ERROR_NONE;
}

int
icmp_get_current_header_length (hicn_type_t type, const hicn_protocol_t * h,
				size_t * header_length)
{
  *header_length = ICMP_HDRLEN;
  return HICN_LIB_ERROR_NONE;
}

int
icmp_get_header_length (hicn_type_t type, const hicn_protocol_t * h,
			size_t * header_length)
{
  size_t child_header_length = 0;
  int rc = CHILD_OPS (get_header_length, type, h, &child_header_length);
  if (rc < 0)
    return rc;

  *header_length = ICMP_HDRLEN + child_header_length;
  return HICN_LIB_ERROR_NONE;
}

int
icmp_get_signature_size (hicn_type_t type, const hicn_protocol_t * h,
			 size_t * signature_size)
{
  return CHILD_OPS (get_signature_size, type, h, signature_size);
}

int
icmp_set_signature_size (hicn_type_t type, hicn_protocol_t * h,
			 size_t signature_size)
{
  return CHILD_OPS (set_signature_size, type, h, signature_size);
}

int
icmp_set_signature_timestamp(hicn_type_t type, hicn_protocol_t * h,
       uint64_t signature_timestamp)
{
  return CHILD_OPS (set_signature_timestamp, type, h, signature_timestamp);
}

int
icmp_get_signature_timestamp (hicn_type_t type, const hicn_protocol_t * h,
       uint64_t * signature_timestamp)
{
  return CHILD_OPS (get_signature_timestamp, type, h, signature_timestamp);
}

int
icmp_set_validation_algorithm (hicn_type_t type, hicn_protocol_t * h,
       uint8_t validation_algorithm)
{
  return CHILD_OPS (set_validation_algorithm, type, h, validation_algorithm);
}

int
icmp_get_validation_algorithm (hicn_type_t type, const hicn_protocol_t * h,
       uint8_t * validation_algorithm)
{
  return CHILD_OPS (get_validation_algorithm, type, h, validation_algorithm);
}

int
icmp_set_key_id (hicn_type_t type, hicn_protocol_t * h,
       uint8_t *key_id)
{
  return CHILD_OPS (set_key_id, type, h, key_id);
}

int
icmp_get_key_id (hicn_type_t type, hicn_protocol_t * h,
       uint8_t **key_id, uint8_t *key_id_size)
{
  return CHILD_OPS (get_key_id, type, h, key_id, key_id_size);
}

DECLARE_HICN_OPS (icmp);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
