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
 * @file protocol/ah.c
 * @brief hICN operations for AH header
 */

#include <string.h>		// memcpy
#include <hicn/common.h>
#include <hicn/error.h>
#include <hicn/header.h>
#include <hicn/ops.h>
#include <hicn/protocol/ah.h>

DECLARE_get_interest_locator (ah, UNEXPECTED);
DECLARE_set_interest_locator (ah, UNEXPECTED);
DECLARE_get_interest_name (ah, UNEXPECTED);
DECLARE_set_interest_name (ah, UNEXPECTED);
DECLARE_get_interest_name_suffix (ah, UNEXPECTED);
DECLARE_set_interest_name_suffix (ah, UNEXPECTED);
DECLARE_get_data_locator (ah, UNEXPECTED);
DECLARE_set_data_locator (ah, UNEXPECTED);
DECLARE_get_data_name (ah, UNEXPECTED);
DECLARE_set_data_name (ah, UNEXPECTED);
DECLARE_get_data_name_suffix (ah, UNEXPECTED);
DECLARE_set_data_name_suffix (ah, UNEXPECTED);
DECLARE_get_data_pathlabel (ah, UNEXPECTED);
DECLARE_set_data_pathlabel (ah, UNEXPECTED);
DECLARE_update_data_pathlabel (ah, UNEXPECTED);
DECLARE_get_lifetime (ah, UNEXPECTED);
DECLARE_set_lifetime (ah, UNEXPECTED);
DECLARE_get_payload_length (ah, UNEXPECTED);
DECLARE_set_payload_length (ah, UNEXPECTED);

int
ah_init_packet_header (hicn_type_t type, hicn_protocol_t * h)
{
  /* *INDENT-OFF* */
  h->ah = (_ah_header_t)
    {
      .nh = (u8)0,
      .payloadlen = (u8)0,
      .reserved = (u16)0,
    };
  /* *INDENT-ON* */
  return CHILD_OPS (init_packet_header, type, h);
}

int
ah_reset_interest_for_hash (hicn_type_t type, hicn_protocol_t * h)
{
  size_t signature_size;
  int rc =
    hicn_ops_vft[type.l1]->get_signature_size (type, h, &signature_size);
  if (rc < 0)
    return rc;
  memset (&(h->ah.validationPayload), 0, signature_size);
  return CHILD_OPS (reset_interest_for_hash, type, h);
}

int
ah_reset_data_for_hash (hicn_type_t type, hicn_protocol_t * h)
{
  size_t signature_size;
  int rc =
    hicn_ops_vft[type.l1]->get_signature_size (type, h, &signature_size);
  if (rc < 0)
    return rc;
  memset (&(h->ah.validationPayload), 0, signature_size);
  return CHILD_OPS (reset_interest_for_hash, type, h);
}

#if 0
int
ah_update_checksums (hicn_type_t type, hicn_protocol_t * h, u16 partial_csum,
		     size_t payload_length)
{
  /* Nothing to do as there is no checksum in AH */
  return HICN_LIB_ERROR_NONE;
}

int
ah_verify_checksums (hicn_type_t type, hicn_protocol_t * h, u16 partial_csum,
		     size_t payload_length)
{
  /* Nothing to do as there is no checksum in AH */
  return HICN_LIB_ERROR_NONE;
}
#endif

int
ah_rewrite_interest (hicn_type_t type, hicn_protocol_t * h,
		     const ip46_address_t * addr_new,
		     ip46_address_t * addr_old)
{
  /* Nothing to do on signature */
  return HICN_LIB_ERROR_NONE;
}

int
ah_rewrite_data (hicn_type_t type, hicn_protocol_t * h,
		 const ip46_address_t * addr_new, ip46_address_t * addr_old,
		 const hicn_faceid_t face_id)
{
  /* Nothing to do on signature */
  return HICN_LIB_ERROR_NONE;
}

int
ah_get_length (hicn_type_t type, const hicn_protocol_t * h, size_t * length)
{
  return HICN_LIB_ERROR_NOT_IMPLEMENTED;
}

int
ah_get_current_header_length (hicn_type_t type, const hicn_protocol_t * h,
			      size_t * header_length)
{
  *header_length = AH_HDRLEN + (h->ah.payloadlen << 2);
  return HICN_LIB_ERROR_NONE;
}

int
ah_get_header_length (hicn_type_t type, const hicn_protocol_t * h,
		      size_t * header_length)
{
  size_t child_header_length = 0;
  int rc = CHILD_OPS (get_header_length, type, h, &child_header_length);
  if (rc < 0)
    return rc;
  *header_length = AH_HDRLEN + (h->ah.payloadlen << 2) + child_header_length;
  return HICN_LIB_ERROR_NONE;
}

int
ah_get_signature (hicn_type_t type, hicn_protocol_t * h, uint8_t ** signature)
{
  *signature = h->ah.validationPayload;
  return HICN_LIB_ERROR_NONE;
}

int
ah_get_signature_size (hicn_type_t type, const hicn_protocol_t * h,
		       size_t * signature_size)
{
  *signature_size = h->ah.payloadlen << 2;
  return HICN_LIB_ERROR_NONE;
}

int
ah_set_signature_size (hicn_type_t type, hicn_protocol_t * h,
		       const size_t signature_size)
{
  h->ah.payloadlen = (u8) (signature_size >> 2);
  return HICN_LIB_ERROR_NONE;
}

int
ah_set_signature_timestamp (hicn_type_t type, hicn_protocol_t * h,
			    uint64_t signature_timestamp)
{
  uint64_t netwok_order_timestamp = htonll (signature_timestamp);
  memcpy (h->ah.timestamp_as_u8, &netwok_order_timestamp, sizeof (uint64_t));
  return HICN_LIB_ERROR_NONE;
}

int
ah_get_signature_timestamp (hicn_type_t type, const hicn_protocol_t * h,
			    uint64_t * signature_timestamp)
{
  memcpy (signature_timestamp, h->ah.timestamp_as_u8, sizeof (uint64_t));
  *signature_timestamp = ntohll (*signature_timestamp);
  return HICN_LIB_ERROR_NONE;
}

int
ah_set_validation_algorithm (hicn_type_t type, hicn_protocol_t * h,
			     uint8_t validation_algorithm)
{
  h->ah.validationAlgorithm = validation_algorithm;
  return HICN_LIB_ERROR_NONE;
}

int
ah_get_validation_algorithm (hicn_type_t type, const hicn_protocol_t * h,
			     uint8_t * validation_algorithm)
{
  *validation_algorithm = h->ah.validationAlgorithm;
  return HICN_LIB_ERROR_NONE;
}

int
ah_set_key_id (hicn_type_t type, hicn_protocol_t * h, uint8_t * key_id)
{
  memcpy (h->ah.keyId, key_id, sizeof (h->ah.keyId));
  return HICN_LIB_ERROR_NONE;
}

int
ah_get_key_id (hicn_type_t type, hicn_protocol_t * h,
	       uint8_t ** key_id, uint8_t * key_id_size)
{
  *key_id = h->ah.keyId;
  *key_id_size = sizeof (h->ah.keyId);
  return HICN_LIB_ERROR_NONE;
}

DECLARE_HICN_OPS (ah);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
