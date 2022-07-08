/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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
 * @file protocol/ah.c
 * @brief hICN operations for AH header
 */

#include <hicn/common.h>
#include <hicn/error.h>
#include <string.h> // memcpy

#include "../ops.h"
#include "ah.h"

DECLARE_get_interest_locator (ah, UNEXPECTED);
DECLARE_set_interest_locator (ah, UNEXPECTED);
DECLARE_get_interest_name (ah, UNEXPECTED);
DECLARE_set_interest_name (ah, UNEXPECTED);
DECLARE_get_interest_name_suffix (ah, UNEXPECTED);
DECLARE_set_interest_name_suffix (ah, UNEXPECTED);
DECLARE_get_type (ah, UNEXPECTED);
DECLARE_set_type (ah, UNEXPECTED);
DECLARE_get_data_locator (ah, UNEXPECTED);
DECLARE_set_data_locator (ah, UNEXPECTED);
DECLARE_get_data_name (ah, UNEXPECTED);
DECLARE_set_data_name (ah, UNEXPECTED);
DECLARE_get_data_name_suffix (ah, UNEXPECTED);
DECLARE_set_data_name_suffix (ah, UNEXPECTED);
DECLARE_get_data_path_label (ah, UNEXPECTED);
DECLARE_set_data_path_label (ah, UNEXPECTED);
DECLARE_update_data_path_label (ah, UNEXPECTED);
DECLARE_get_lifetime (ah, UNEXPECTED);
DECLARE_set_lifetime (ah, UNEXPECTED);
// DECLARE_get_payload_len (ah, UNEXPECTED);
DECLARE_set_payload_len (ah, UNEXPECTED);
DECLARE_get_payload_type (ah, UNEXPECTED);
DECLARE_set_payload_type (ah, UNEXPECTED);
DECLARE_is_last_data (ah, UNEXPECTED);
DECLARE_set_last_data (ah, UNEXPECTED);
DECLARE_get_ttl (ah, UNEXPECTED);
DECLARE_set_ttl (ah, UNEXPECTED);
DECLARE_get_src_port (ah, UNEXPECTED);
DECLARE_set_src_port (ah, UNEXPECTED);
DECLARE_get_dst_port (ah, UNEXPECTED);
DECLARE_set_dst_port (ah, UNEXPECTED);

int
ah_init_packet_header (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  pkbuf->ah = pkbuf->len;
  if (AH_HDRLEN > pkbuf->buffer_size - pkbuf->len)
    return -1;
  pkbuf->len += AH_HDRLEN;

  _ah_header_t *ah = pkbuf_get_ah (pkbuf);

  /* clang-format off */
  *ah = (_ah_header_t){
    .nh = (u8) 0,
    .payloadlen = (u8) 0,
    .reserved = (u16) 0,
  };
  /* clang-format on */
  return CALL_CHILD (init_packet_header, pkbuf, pos);
}

int
ah_reset_interest_for_hash (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  _ah_header_t *ah = pkbuf_get_ah (pkbuf);

  size_t signature_size;
  int rc = CALL (get_signature_size, pkbuf, &signature_size);
  if (rc < 0)
    return rc;
  memset (&(ah->validationPayload), 0, signature_size);
  ah->signaturePadding = 0;
  return CALL_CHILD (reset_interest_for_hash, pkbuf, pos);
}

int
ah_reset_data_for_hash (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  _ah_header_t *ah = pkbuf_get_ah (pkbuf);

  size_t signature_size;
  int rc = CALL (get_signature_size, pkbuf, &signature_size);
  if (rc < 0)
    return rc;
  memset (&(ah->validationPayload), 0, signature_size);
  ah->signaturePadding = 0;
  return CALL_CHILD (reset_interest_for_hash, pkbuf, pos);
}

int
ah_update_checksums (const hicn_packet_buffer_t *pkbuf, size_t pos,
		     u16 partial_csum, size_t payload_len)
{
  /* Nothing to do as there is no checksum in AH */
  return HICN_LIB_ERROR_NONE;
}

int
ah_update_checksums_incremental (const hicn_packet_buffer_t *pkbuf, size_t pos,
				 u16 *old_val, u16 *new_val, u8 size,
				 bool skip_first)
{
  return CALL_CHILD (update_checksums_incremental, pkbuf, pos, old_val,
		     new_val, size, false);
}

int
ah_verify_checksums (const hicn_packet_buffer_t *pkbuf, size_t pos,
		     u16 partial_csum, size_t payload_len)
{
  /* Nothing to do as there is no checksum in AH */
  return HICN_LIB_ERROR_NONE;
}

int
ah_rewrite_interest (const hicn_packet_buffer_t *pkbuf, size_t pos,
		     const hicn_ip_address_t *addr_new,
		     hicn_ip_address_t *addr_old)
{
  /* Nothing to do on signature */
  return HICN_LIB_ERROR_NONE;
}

int
ah_rewrite_data (const hicn_packet_buffer_t *pkbuf, size_t pos,
		 const hicn_ip_address_t *addr_new,
		 hicn_ip_address_t *addr_old, const hicn_faceid_t face_id,
		 u8 reset_pl)
{
  /* Nothing to do on signature */
  return HICN_LIB_ERROR_NONE;
}

int
ah_get_signature (const hicn_packet_buffer_t *pkbuf, size_t pos,
		  uint8_t **signature)
{
  _ah_header_t *ah = pkbuf_get_ah (pkbuf);

  *signature = ah->validationPayload;
  return HICN_LIB_ERROR_NONE;
}

int
ah_has_signature (const hicn_packet_buffer_t *pkbuf, size_t pos, bool *flag)
{
  *flag = true;
  return HICN_LIB_ERROR_NONE;
}

int
ah_get_signature_size (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       size_t *signature_size)
{
  _ah_header_t *ah = pkbuf_get_ah (pkbuf);

  *signature_size = ah->payloadlen << 2;
  return HICN_LIB_ERROR_NONE;
}

int
ah_set_signature_size (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       size_t signature_size)
{
  _ah_header_t *ah = pkbuf_get_ah (pkbuf);

  ah->payloadlen = signature_size >> 2;
  return HICN_LIB_ERROR_NONE;
}

int
ah_set_signature_timestamp (const hicn_packet_buffer_t *pkbuf, size_t pos,
			    uint64_t signature_timestamp)
{
  _ah_header_t *ah = pkbuf_get_ah (pkbuf);

  uint64_t netwok_order_timestamp = hicn_net_to_host_64 (signature_timestamp);
  memcpy (ah->timestamp_as_u8, &netwok_order_timestamp, sizeof (uint64_t));
  return HICN_LIB_ERROR_NONE;
}

int
ah_get_signature_timestamp (const hicn_packet_buffer_t *pkbuf, size_t pos,
			    uint64_t *signature_timestamp)
{
  _ah_header_t *ah = pkbuf_get_ah (pkbuf);

  memcpy (signature_timestamp, ah->timestamp_as_u8, sizeof (uint64_t));
  *signature_timestamp = hicn_host_to_net_64 (*signature_timestamp);
  return HICN_LIB_ERROR_NONE;
}

int
ah_set_validation_algorithm (const hicn_packet_buffer_t *pkbuf, size_t pos,
			     uint8_t validation_algorithm)
{
  _ah_header_t *ah = pkbuf_get_ah (pkbuf);

  ah->validationAlgorithm = validation_algorithm;
  return HICN_LIB_ERROR_NONE;
}

int
ah_get_validation_algorithm (const hicn_packet_buffer_t *pkbuf, size_t pos,
			     uint8_t *validation_algorithm)
{
  _ah_header_t *ah = pkbuf_get_ah (pkbuf);

  *validation_algorithm = ah->validationAlgorithm;
  return HICN_LIB_ERROR_NONE;
}

int
ah_set_signature_padding (const hicn_packet_buffer_t *pkbuf, size_t pos,
			  size_t padding)
{
  _ah_header_t *ah = pkbuf_get_ah (pkbuf);

  ah->signaturePadding = padding;
  return HICN_LIB_ERROR_NONE;
}

int
ah_get_signature_padding (const hicn_packet_buffer_t *pkbuf, size_t pos,
			  size_t *padding)
{
  _ah_header_t *ah = pkbuf_get_ah (pkbuf);

  *padding = ah->signaturePadding;
  return HICN_LIB_ERROR_NONE;
}

int
ah_set_key_id (const hicn_packet_buffer_t *pkbuf, size_t pos, uint8_t *key_id,
	       size_t size)
{
  _ah_header_t *ah = pkbuf_get_ah (pkbuf);

  if (size != sizeof (ah->keyId))
    return HICN_LIB_ERROR_INVALID_PARAMETER;

  memcpy (ah->keyId, key_id, sizeof (ah->keyId));
  return HICN_LIB_ERROR_NONE;
}

int
ah_get_key_id (const hicn_packet_buffer_t *pkbuf, size_t pos, uint8_t **key_id,
	       uint8_t *key_id_size)
{
  _ah_header_t *ah = pkbuf_get_ah (pkbuf);

  *key_id = ah->keyId;
  *key_id_size = sizeof (ah->keyId);
  return HICN_LIB_ERROR_NONE;
}

DECLARE_HICN_OPS (ah, AH_HDRLEN);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
