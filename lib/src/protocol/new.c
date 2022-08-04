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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

DECLARE_get_ttl (new, UNEXPECTED);
DECLARE_set_ttl (new, UNEXPECTED);
DECLARE_get_src_port (new, UNEXPECTED);
DECLARE_set_src_port (new, UNEXPECTED);
DECLARE_get_dst_port (new, UNEXPECTED);
DECLARE_set_dst_port (new, UNEXPECTED);

int
new_init_packet_header (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  pkbuf->newhdr = pkbuf->len;
  if (NEW_HDRLEN > pkbuf->buffer_size - pkbuf->len)
    return -1;
  pkbuf->len += NEW_HDRLEN;

  _new_header_t *new = pkbuf_get_new (pkbuf);

  hicn_packet_format_t format = hicn_packet_get_format (pkbuf);

  memset (new, 0, sizeof (_new_header_t));
  _set_new_header_version (new);
  uint8_t ah_flag =
    format.as_u8[pos + 1] == IPPROTO_AH ? HICN_NEW_FLAG_SIG : 0;
  new->flags |= ah_flag;

  return CALL_CHILD (init_packet_header, pkbuf, pos);
}

int
new_get_type (const hicn_packet_buffer_t *pkbuf, const size_t pos,
	      hicn_packet_type_t *type)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  /* Interest packets have the INT bit set */
  if (new->flags & HICN_NEW_FLAG_INT)
    *type = HICN_PACKET_TYPE_INTEREST;
  else
    *type = HICN_PACKET_TYPE_DATA;
  return HICN_LIB_ERROR_NONE;
}

int
new_set_type (const hicn_packet_buffer_t *pkbuf, size_t pos,
	      hicn_packet_type_t type)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  switch (type)
    {
    case HICN_PACKET_TYPE_INTEREST:
      new->flags |= HICN_NEW_FLAG_INT;
      break;
    case HICN_PACKET_TYPE_DATA:
      new->flags &= ~HICN_NEW_FLAG_INT;
      break;
    default:
      return -1;
    }
  return HICN_LIB_ERROR_NONE;
}

int
new_get_interest_locator (const hicn_packet_buffer_t *pkbuf, size_t pos,
			  hicn_ip_address_t *ip_address)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);
  _unused (new);

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_INTEREST);
  return HICN_LIB_ERROR_NONE;
}

int
new_set_interest_locator (const hicn_packet_buffer_t *pkbuf, size_t pos,
			  const hicn_ip_address_t *ip_address)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);
  _unused (new);

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_INTEREST);

  return HICN_LIB_ERROR_NONE;
}

int
new_get_interest_name (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       hicn_name_t *name)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_INTEREST);

  name->prefix = new->prefix;
  name->suffix = ntohl (new->suffix);
  return HICN_LIB_ERROR_NONE;
}

int
new_set_interest_name (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       const hicn_name_t *name)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  int rc = new_set_type (pkbuf, pos, HICN_PACKET_TYPE_INTEREST);
  if (rc)
    return rc;

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_INTEREST);

  new->prefix = name->prefix;
  new->suffix = htonl (name->suffix);
  return HICN_LIB_ERROR_NONE;
}

int
new_get_interest_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      hicn_name_suffix_t *suffix)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_INTEREST);

  *suffix = ntohl (new->suffix);
  return HICN_LIB_ERROR_NONE;
}

int
new_set_interest_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      const hicn_name_suffix_t *suffix)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_INTEREST);

  new->suffix = htonl (*suffix);
  return HICN_LIB_ERROR_NONE;
}

int
new_reset_interest_for_hash (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);
  _unused (new);

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_INTEREST);

  return CALL_CHILD (init_packet_header, pkbuf, pos);
}

int
new_get_data_locator (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      hicn_ip_address_t *ip_address)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);
  _unused (new);

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_INTEREST);

  return HICN_LIB_ERROR_NONE;
}

int
new_set_data_locator (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      const hicn_ip_address_t *ip_address)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);
  _unused (new);

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_DATA);

  return HICN_LIB_ERROR_NONE;
}

int
new_get_data_name (const hicn_packet_buffer_t *pkbuf, size_t pos,
		   hicn_name_t *name)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_DATA);

  name->prefix = new->prefix;
  name->suffix = ntohl (new->suffix);
  return HICN_LIB_ERROR_NONE;
}

int
new_set_data_name (const hicn_packet_buffer_t *pkbuf, size_t pos,
		   const hicn_name_t *name)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  int rc = new_set_type (pkbuf, pos, HICN_PACKET_TYPE_DATA);
  if (rc)
    return rc;

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_DATA);

  new->prefix = name->prefix;
  new->suffix = htonl (name->suffix);
  return HICN_LIB_ERROR_NONE;
}

int
new_get_data_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			  hicn_name_suffix_t *suffix)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_DATA);

  *suffix = ntohl (new->suffix);
  return HICN_LIB_ERROR_NONE;
}

int
new_set_data_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			  const hicn_name_suffix_t *suffix)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_DATA);

  new->suffix = htonl (*suffix);
  return HICN_LIB_ERROR_NONE;
}

int
new_get_data_path_label (const hicn_packet_buffer_t *pkbuf, size_t pos,
			 hicn_path_label_t *path_label)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_DATA);

  *path_label = ntohl (new->path_label);
  return HICN_LIB_ERROR_NONE;
}

int
new_set_data_path_label (const hicn_packet_buffer_t *pkbuf, size_t pos,
			 hicn_path_label_t path_label)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_DATA);

  new->path_label = htonl (path_label);
  return HICN_LIB_ERROR_NONE;
}

int
new_update_data_path_label (const hicn_packet_buffer_t *pkbuf, size_t pos,
			    const hicn_faceid_t face_id)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  hicn_path_label_t new_pl;
  update_path_label (new->path_label, face_id, &new_pl);
  new->path_label = new_pl;
  return HICN_LIB_ERROR_NONE;
}

int
new_reset_data_for_hash (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  return CALL_CHILD (reset_data_for_hash, pkbuf, pos);
}

int
new_get_lifetime (const hicn_packet_buffer_t *pkbuf, size_t pos,
		  hicn_lifetime_t *lifetime)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  *lifetime = ntohl (new->lifetime);
  return HICN_LIB_ERROR_NONE;
}

int
new_set_lifetime (const hicn_packet_buffer_t *pkbuf, size_t pos,
		  const hicn_lifetime_t lifetime)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  new->lifetime = htonl (lifetime);
  return HICN_LIB_ERROR_NONE;
}

int
new_update_checksums (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      u16 partial_csum, size_t payload_len)
{
  return HICN_LIB_ERROR_NONE;
}

int
new_update_checksums_incremental (const hicn_packet_buffer_t *pkbuf,
				  size_t pos, u16 *old_val, u16 *new_val,
				  u8 size, bool skip_first)
{
  return HICN_LIB_ERROR_NONE;
}

int
new_verify_checksums (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      u16 partial_csum, size_t payload_len)
{
  return HICN_LIB_ERROR_NONE;
}

int
new_rewrite_interest (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      const hicn_ip_address_t *addr_new,
		      hicn_ip_address_t *addr_old)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);
  _unused (new);

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_INTEREST);

  return HICN_LIB_ERROR_NONE;
}

int
new_rewrite_data (const hicn_packet_buffer_t *pkbuf, size_t pos,
		  const hicn_ip_address_t *addr_new,
		  hicn_ip_address_t *addr_old, const hicn_faceid_t face_id,
		  u8 reset_pl)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);
  _unused (new);

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_DATA);

  return HICN_LIB_ERROR_NONE;
}

int
new_set_payload_len (const hicn_packet_buffer_t *pkbuf, size_t pos,
		     size_t payload_len)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  /*
   * The value we have to store in the header is the sum of headers following
   * the current header + the new payload size
   */

  size_t child_header_len =
    (pkbuf->payload - pkbuf->newhdr) - sizeof (_new_header_t);
  new->payload_len = htons ((u16) child_header_len + payload_len);
  return HICN_LIB_ERROR_NONE;
}

int
new_get_signature_size (const hicn_packet_buffer_t *pkbuf, size_t pos,
			size_t *signature_size)
{
  return CALL_CHILD (get_signature_size, pkbuf, pos, signature_size);
}

int
new_set_signature_size (const hicn_packet_buffer_t *pkbuf, size_t pos,
			size_t signature_size)
{
  return CALL_CHILD (set_signature_size, pkbuf, pos, signature_size);
}

int
new_set_signature_padding (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   size_t padding)
{
  return CALL_CHILD (set_signature_padding, pkbuf, pos, padding);
}

int
new_get_signature_padding (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   size_t *padding)
{
  return CALL_CHILD (get_signature_padding, pkbuf, pos, padding);
}

int
new_set_signature_timestamp (const hicn_packet_buffer_t *pkbuf, size_t pos,
			     uint64_t signature_timestamp)
{
  return CALL_CHILD (set_signature_timestamp, pkbuf, pos, signature_timestamp);
}

int
new_get_signature_timestamp (const hicn_packet_buffer_t *pkbuf, size_t pos,
			     uint64_t *signature_timestamp)
{
  return CALL_CHILD (get_signature_timestamp, pkbuf, pos, signature_timestamp);
}

int
new_set_validation_algorithm (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      uint8_t validation_algorithm)
{
  return CALL_CHILD (set_validation_algorithm, pkbuf, pos,
		     validation_algorithm);
}

int
new_get_validation_algorithm (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      uint8_t *validation_algorithm)
{
  return CALL_CHILD (get_validation_algorithm, pkbuf, pos,
		     validation_algorithm);
}

int
new_set_key_id (const hicn_packet_buffer_t *pkbuf, size_t pos, uint8_t *key_id,
		size_t key_len)
{
  return CALL_CHILD (set_key_id, pkbuf, pos, key_id, key_len);
}

int
new_get_key_id (const hicn_packet_buffer_t *pkbuf, size_t pos,
		uint8_t **key_id, uint8_t *key_id_size)
{
  return CALL_CHILD (get_key_id, pkbuf, pos, key_id, key_id_size);
}

int
new_get_signature (const hicn_packet_buffer_t *pkbuf, size_t pos,
		   uint8_t **signature)
{
  return CALL_CHILD (get_signature, pkbuf, pos, signature);
}

int
new_has_signature (const hicn_packet_buffer_t *pkbuf, size_t pos, bool *flag)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  return new->flags &HICN_NEW_FLAG_SIG;
}

int
new_get_payload_type (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      hicn_payload_type_t *payload_type)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  *payload_type = ((new->flags &HICN_NEW_FLAG_MAN) == HICN_NEW_FLAG_MAN);
  return HICN_LIB_ERROR_NONE;
}

int
new_set_payload_type (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      hicn_payload_type_t payload_type)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  if (payload_type != HPT_DATA && payload_type != HPT_MANIFEST)
    return HICN_LIB_ERROR_INVALID_PARAMETER;

  if (payload_type)
    new->flags |= HICN_NEW_FLAG_MAN;
  else
    new->flags &= ~HICN_NEW_FLAG_MAN;

  return HICN_LIB_ERROR_NONE;
}

int
new_is_last_data (const hicn_packet_buffer_t *pkbuf, size_t pos, int *is_last)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_DATA);

  *is_last = new->flags &HICN_NEW_FLAG_LST;
  return HICN_LIB_ERROR_NONE;
}

int
new_set_last_data (const hicn_packet_buffer_t *pkbuf, size_t pos)
{
  _new_header_t *new = pkbuf_get_new (pkbuf);

  hicn_packet_type_t type;
  _ASSERT (new_get_type (pkbuf, pos, &type) == 0);
  _ASSERT (type == HICN_PACKET_TYPE_DATA);

  new->flags |= HICN_NEW_FLAG_LST;
  return HICN_LIB_ERROR_NONE;
}

DECLARE_HICN_OPS (new, NEW_HDRLEN);

#pragma GCC diagnostic pop

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
