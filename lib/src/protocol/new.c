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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

static int
is_interest (u8 flags)
{
  return flags & HICN_NEW_FLAG_INT;
}

int
new_init_packet_header (hicn_type_t type, hicn_protocol_t *h)
{
  memset (&h->newhdr, 0, sizeof (h->newhdr));
  _set_new_header_version (&h->newhdr);
  uint8_t ah_flag = type.l2 == IPPROTO_AH ? HICN_NEW_FLAG_SIG : 0;
  h->newhdr.flags |= ah_flag;

  return CHILD_OPS (init_packet_header, type, h);
}

int
new_is_interest (hicn_type_t type, const hicn_protocol_t *h, int *is_interest)
{
  *is_interest = (h->newhdr.flags & HICN_NEW_FLAG_INT) != 0;
  return HICN_LIB_ERROR_NONE;
}

int
new_mark_packet_as_interest (hicn_type_t type, hicn_protocol_t *h)
{
  h->newhdr.flags |= HICN_NEW_FLAG_INT;
  return HICN_LIB_ERROR_NONE;
}

int
new_mark_packet_as_data (hicn_type_t type, hicn_protocol_t *h)
{
  h->newhdr.flags &= ~HICN_NEW_FLAG_INT;
  return HICN_LIB_ERROR_NONE;
}

int
new_get_interest_locator (hicn_type_t type, const hicn_protocol_t *h,
			  ip_address_t *ip_address)
{
  assert (is_interest (h->newhdr.flags));
  return HICN_LIB_ERROR_NONE;
}

int
new_set_interest_locator (hicn_type_t type, hicn_protocol_t *h,
			  const ip_address_t *ip_address)
{
  assert (is_interest (h->newhdr.flags));
  return HICN_LIB_ERROR_NONE;
}

int
new_get_interest_name (hicn_type_t type, const hicn_protocol_t *h,
		       hicn_name_t *name)
{
  assert (is_interest (h->newhdr.flags));
  name->prefix = h->newhdr.prefix;
  name->suffix = ntohl (h->newhdr.suffix);
  return HICN_LIB_ERROR_NONE;
}

int
new_set_interest_name (hicn_type_t type, hicn_protocol_t *h,
		       const hicn_name_t *name)
{
  int rc = new_mark_packet_as_interest (type, h);
  if (rc)
    return rc;

  assert (is_interest (h->newhdr.flags));
  h->newhdr.prefix = name->prefix;
  h->newhdr.suffix = htonl (name->suffix);
  return HICN_LIB_ERROR_NONE;
}

int
new_get_interest_name_suffix (hicn_type_t type, const hicn_protocol_t *h,
			      hicn_name_suffix_t *suffix)
{
  assert (is_interest (h->newhdr.flags));
  *suffix = ntohl (h->newhdr.suffix);
  return HICN_LIB_ERROR_NONE;
}

int
new_set_interest_name_suffix (hicn_type_t type, hicn_protocol_t *h,
			      const hicn_name_suffix_t *suffix)
{
  assert (is_interest (h->newhdr.flags));
  h->newhdr.suffix = htonl (*suffix);
  return HICN_LIB_ERROR_NONE;
}

int
new_reset_interest_for_hash (hicn_type_t type, hicn_protocol_t *h)
{
  assert (is_interest (h->newhdr.flags));
  return CHILD_OPS (init_packet_header, type, h);
}

int
new_get_data_locator (hicn_type_t type, const hicn_protocol_t *h,
		      ip_address_t *ip_address)
{
  assert (!is_interest (h->newhdr.flags));
  return HICN_LIB_ERROR_NONE;
}

int
new_set_data_locator (hicn_type_t type, hicn_protocol_t *h,
		      const ip_address_t *ip_address)
{
  assert (!is_interest (h->newhdr.flags));
  return HICN_LIB_ERROR_NONE;
}

int
new_get_data_name (hicn_type_t type, const hicn_protocol_t *h,
		   hicn_name_t *name)
{
  assert (!is_interest (h->newhdr.flags));
  name->prefix = h->newhdr.prefix;
  name->suffix = ntohl (h->newhdr.suffix);
  return HICN_LIB_ERROR_NONE;
}

int
new_set_data_name (hicn_type_t type, hicn_protocol_t *h,
		   const hicn_name_t *name)
{
  new_mark_packet_as_data (type, h);
  assert (!is_interest (h->newhdr.flags));
  h->newhdr.prefix = name->prefix;
  h->newhdr.suffix = htonl (name->suffix);
  return HICN_LIB_ERROR_NONE;
}

int
new_get_data_name_suffix (hicn_type_t type, const hicn_protocol_t *h,
			  hicn_name_suffix_t *suffix)
{
  assert (!is_interest (h->newhdr.flags));
  *suffix = ntohl (h->newhdr.suffix);
  return HICN_LIB_ERROR_NONE;
}

int
new_set_data_name_suffix (hicn_type_t type, hicn_protocol_t *h,
			  const hicn_name_suffix_t *suffix)
{
  assert (!is_interest (h->newhdr.flags));
  h->newhdr.suffix = htonl (*suffix);
  return HICN_LIB_ERROR_NONE;
}

int
new_get_data_pathlabel (hicn_type_t type, const hicn_protocol_t *h,
			u32 *pathlabel)
{
  assert (!is_interest (h->newhdr.flags));
  *pathlabel = h->newhdr.path_label;
  return HICN_LIB_ERROR_NONE;
}

int
new_set_data_pathlabel (hicn_type_t type, hicn_protocol_t *h,
			const u32 pathlabel)
{
  assert (!is_interest (h->newhdr.flags));
  h->newhdr.path_label = pathlabel;
  return HICN_LIB_ERROR_NONE;
}

int
new_update_data_pathlabel (hicn_type_t type, hicn_protocol_t *h,
			   const hicn_faceid_t face_id)
{
  hicn_pathlabel_t new_pl;
  update_pathlabel (h->newhdr.path_label, face_id, &new_pl);
  h->newhdr.path_label = new_pl;
  return HICN_LIB_ERROR_NONE;
}

int
new_reset_data_for_hash (hicn_type_t type, hicn_protocol_t *h)
{
  return CHILD_OPS (reset_data_for_hash, type, h);
}

int
new_get_lifetime (hicn_type_t type, const hicn_protocol_t *h,
		  hicn_lifetime_t *lifetime)
{
  *lifetime = ntohl (h->newhdr.lifetime);
  return HICN_LIB_ERROR_NONE;
}

int
new_set_lifetime (hicn_type_t type, hicn_protocol_t *h,
		  const hicn_lifetime_t lifetime)
{
  h->newhdr.lifetime = htonl (lifetime);
  return HICN_LIB_ERROR_NONE;
}

int
new_update_checksums (hicn_type_t type, hicn_protocol_t *h, u16 partial_csum,
		      size_t payload_length)
{
  return HICN_LIB_ERROR_NONE;
}

int
new_verify_checksums (hicn_type_t type, hicn_protocol_t *h, u16 partial_csum,
		      size_t payload_length)
{
  return HICN_LIB_ERROR_NONE;
}

int
new_rewrite_interest (hicn_type_t type, hicn_protocol_t *h,
		      const ip_address_t *addr_new, ip_address_t *addr_old)
{
  assert (is_interest (h->newhdr.flags));
  return HICN_LIB_ERROR_NONE;
}

int
new_rewrite_data (hicn_type_t type, hicn_protocol_t *h,
		  const ip_address_t *addr_new, ip_address_t *addr_old,
		  const hicn_faceid_t face_id, u8 reset_pl)
{
  assert (!is_interest (h->newhdr.flags));
  return HICN_LIB_ERROR_NONE;
}

int
new_get_length (hicn_type_t type, const hicn_protocol_t *h,
		size_t *header_length)
{
  *header_length = NEW_HDRLEN + ntohs (h->newhdr.payload_length);
  return HICN_LIB_ERROR_NONE;
}

int
new_get_current_header_length (hicn_type_t type, const hicn_protocol_t *h,
			       size_t *header_length)
{
  *header_length = NEW_HDRLEN;
  return HICN_LIB_ERROR_NONE;
}

int
new_get_header_length (hicn_type_t type, const hicn_protocol_t *h,
		       size_t *header_length)
{
  size_t child_header_length = 0;
  int rc = CHILD_OPS (get_header_length, type, h, &child_header_length);
  if (rc < 0)
    return rc;
  *header_length = NEW_HDRLEN + child_header_length;
  return HICN_LIB_ERROR_NONE;
}

int
new_get_payload_length (hicn_type_t type, const hicn_protocol_t *h,
			size_t *payload_length)
{
  size_t child_header_length = 0;
  int rc = CHILD_OPS (get_header_length, type, h, &child_header_length);
  if (rc < 0)
    return rc;
  *payload_length = ntohs (h->newhdr.payload_length) - child_header_length;
  return HICN_LIB_ERROR_NONE;
}

int
new_set_payload_length (hicn_type_t type, hicn_protocol_t *h,
			size_t payload_length)
{
  size_t child_header_length = 0;
  int rc = CHILD_OPS (get_header_length, type, h, &child_header_length);
  if (rc < 0)
    return rc;
  h->newhdr.payload_length =
    htons ((u_short) (payload_length + child_header_length));
  return HICN_LIB_ERROR_NONE;
}

int
new_get_signature_size (hicn_type_t type, const hicn_protocol_t *h,
			size_t *signature_size)
{
  return CHILD_OPS (get_signature_size, type, h, signature_size);
}

int
new_set_signature_size (hicn_type_t type, hicn_protocol_t *h,
			size_t signature_size)
{
  return CHILD_OPS (set_signature_size, type, h, signature_size);
}

int
new_set_signature_padding (hicn_type_t type, hicn_protocol_t *h,
			   size_t padding)
{
  return CHILD_OPS (set_signature_padding, type, h, padding);
}

int
new_get_signature_padding (hicn_type_t type, const hicn_protocol_t *h,
			   size_t *padding)
{
  return CHILD_OPS (get_signature_padding, type, h, padding);
}

int
new_set_signature_timestamp (hicn_type_t type, hicn_protocol_t *h,
			     uint64_t signature_timestamp)
{
  return CHILD_OPS (set_signature_timestamp, type, h, signature_timestamp);
}

int
new_get_signature_timestamp (hicn_type_t type, const hicn_protocol_t *h,
			     uint64_t *signature_timestamp)
{
  return CHILD_OPS (get_signature_timestamp, type, h, signature_timestamp);
}

int
new_set_validation_algorithm (hicn_type_t type, hicn_protocol_t *h,
			      uint8_t validation_algorithm)
{
  return CHILD_OPS (set_validation_algorithm, type, h, validation_algorithm);
}

int
new_get_validation_algorithm (hicn_type_t type, const hicn_protocol_t *h,
			      uint8_t *validation_algorithm)
{
  return CHILD_OPS (get_validation_algorithm, type, h, validation_algorithm);
}

int
new_set_key_id (hicn_type_t type, hicn_protocol_t *h, uint8_t *key_id)
{
  return CHILD_OPS (set_key_id, type, h, key_id);
}

int
new_get_key_id (hicn_type_t type, hicn_protocol_t *h, uint8_t **key_id,
		uint8_t *key_id_size)
{
  return CHILD_OPS (get_key_id, type, h, key_id, key_id_size);
}

int
new_get_signature (hicn_type_t type, hicn_protocol_t *h, uint8_t **signature)
{
  return CHILD_OPS (get_signature, type, h, signature);
}

int
new_get_payload_type (hicn_type_t type, const hicn_protocol_t *h,
		      hicn_payload_type_t *payload_type)
{
  *payload_type = ((h->newhdr.flags & HICN_NEW_FLAG_MAN) == HICN_NEW_FLAG_MAN);
  return HICN_LIB_ERROR_NONE;
}

int
new_set_payload_type (hicn_type_t type, hicn_protocol_t *h,
		      hicn_payload_type_t payload_type)
{
  if (payload_type != HPT_DATA && payload_type != HPT_MANIFEST)
    return HICN_LIB_ERROR_INVALID_PARAMETER;

  if (payload_type)
    h->newhdr.flags |= HICN_NEW_FLAG_MAN;
  else
    h->newhdr.flags &= ~HICN_NEW_FLAG_MAN;

  return HICN_LIB_ERROR_NONE;
}

int
new_is_last_data (hicn_type_t type, const hicn_protocol_t *h, int *is_last)
{
  assert (!is_interest (h->newhdr.flags));
  *is_last = h->newhdr.flags & HICN_NEW_FLAG_LST;
  return HICN_LIB_ERROR_NONE;
}

int
new_set_last_data (hicn_type_t type, hicn_protocol_t *h)
{
  assert (!is_interest (h->newhdr.flags));
  h->newhdr.flags |= HICN_NEW_FLAG_LST;
  return HICN_LIB_ERROR_NONE;
}

DECLARE_HICN_OPS (new);

#pragma GCC diagnostic pop

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
