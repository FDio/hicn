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
 * @file base.h
 * @brief Protocol-independent packet operations
 */

#ifndef HICN_OPS_H
#define HICN_OPS_H

#include <stdlib.h>

#include "error.h"
#include "header.h"
#include "name.h"

/*
 * hICN operations on packets
 *
 * All prototypes take an hicn_type_t parameter as their first argument, as this
 * decides the sequence of protocols that are being used by the different
 * operations.
 */

typedef struct hicn_ops_s
{
  /**
   * @brief Initialize the headers of the hicn packet
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the packet
   */
  int (*init_packet_header) (hicn_type_t type, hicn_protocol_t * h);

  /**
   * @brief Retrieves an Interest locator
   * @param [in] type - hICN packet type
   * @param [in] h - Buffer holding the Interest packet
   * @param [out] ip_address - Retrieved locator
   * @return hICN error code
   */
  int (*get_interest_locator) (hicn_type_t type, const hicn_protocol_t * h,
			       ip46_address_t * ip_address);

  /**
   * @brief Sets an Interest locator
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Interest packet
   * @param [in] ip_address - Locator to set
   * @return hICN error code
   */
  int (*set_interest_locator) (hicn_type_t type, hicn_protocol_t * h,
			       const ip46_address_t * ip_address);

  /**
   * @brief Retrieves an Interest name
   * @param [in] type - hICN packet type
   * @param [in] h - Buffer holding the Interest packet
   * @param [out] name - Retrieved name
   * @return hICN error code
   */
  int (*get_interest_name) (hicn_type_t type, const hicn_protocol_t * h,
			    hicn_name_t * name);

  /**
   * @brief Sets an Interest name
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Interest packet
   * @param [in] name - Name to set
   * @return hICN error code
   */
  int (*set_interest_name) (hicn_type_t type, hicn_protocol_t * h,
			    const hicn_name_t * name);

  /**
   * @brief Retrieves an Interest name suffix
   * @param [in] type - hICN packet type
   * @param [in] h - Buffer holding the Interest packet
   * @param [out] suffix - Retrieved name suffix
   * @return hICN error code
   */
  int (*get_interest_name_suffix) (hicn_type_t type,
				   const hicn_protocol_t * h,
				   hicn_name_suffix_t * suffix);

  /**
   * @brief Sets an Interest name suffix
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Interest packet
   * @param [in] suffix - Name suffix to set
   * @return hICN error code
   */
  int (*set_interest_name_suffix) (hicn_type_t type, hicn_protocol_t * h,
				   const hicn_name_suffix_t * suffix);

  /**
   * @brief Clear the necessary Interest fields in order to hash it
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Interest packet
   * @return hICN error code
   */
  int (*reset_interest_for_hash) (hicn_type_t type, hicn_protocol_t * h);

  /**
   * @brief Retrieves a Data locator
   * @param [in] type - hICN packet type
   * @param [in] h - Buffer holding the Data packet
   * @param [out] ip_address - Retrieved locator
   * @return hICN error code
   */
  int (*get_data_locator) (hicn_type_t type, const hicn_protocol_t * h,
			   ip46_address_t * ip_address);

  /**
   * @brief Sets a Data locator
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Data packet
   * @param [in] ip_address - Locator to set
   * @return hICN error code
   */
  int (*set_data_locator) (hicn_type_t type, hicn_protocol_t * h,
			   const ip46_address_t * ip_address);

  /**
   * @brief Retrieves a Data name
   * @param [in] type - hICN packet type
   * @param [in] h - Buffer holding the Data packet
   * @param [out] name - Retrieved name
   * @return hICN error code
   */
  int (*get_data_name) (hicn_type_t type, const hicn_protocol_t * h,
			hicn_name_t * name);

  /**
   * @brief Sets a Data name
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Data packet
   * @param [in] name - Name to set
   * @return hICN error code
   */
  int (*set_data_name) (hicn_type_t type, hicn_protocol_t * h,
			const hicn_name_t * name);

  /**
   * @brief Retrieves a Data name suffix
   * @param [in] type - hICN packet type
   * @param [in] h - Buffer holding the Data packet
   * @param [out] suffix - Retrieved name suffix
   * @return hICN error code
   */
  int (*get_data_name_suffix) (hicn_type_t type, const hicn_protocol_t * h,
			       hicn_name_suffix_t * suffix);

  /**
   * @brief Sets a Data name suffix
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Data packet
   * @param [in] suffix - Name suffix to set
   * @return hICN error code
   */
  int (*set_data_name_suffix) (hicn_type_t type, hicn_protocol_t * h,
			       const hicn_name_suffix_t * suffix);

  /**
   * @brief Retrieves a Data pathlabel
   * @param [in] type - hICN packet type
   * @param [in] h - Buffer holding the Data packet
   * @param [out] pathlabel - Retrieved pathlabel
   * @return hICN error code
   */
  int (*get_data_pathlabel) (hicn_type_t type, const hicn_protocol_t * h,
			     u32 * pathlabel);

  /**
   * @brief Sets a Data pathlabel
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Data packet
   * @param [in] pathlabel - Pathlabel to set
   * @return hICN error code
   */
  int (*set_data_pathlabel) (hicn_type_t type, hicn_protocol_t * h,
			     const u32 pathlabel);

  /**
   * @brief Update a Data pathlabel with a new face identifier
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Data packet
   * @param [in] pathlabel - Face identifier used to update pathlabel
   * @return hICN error code
   */
  int (*update_data_pathlabel) (hicn_type_t type, hicn_protocol_t * h,
				const hicn_faceid_t face_id);

  /**
   * @brief Clear the necessary Data fields in order to hash it
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Data packet
   * @return hICN error code
   */
  int (*reset_data_for_hash) (hicn_type_t type, hicn_protocol_t * h);

  /**
   * @brief Retrieves an Interest or Data lifetime
   * @param [in] type - hICN packet type
   * @param [in] h - Buffer holding the Interest or Data packet
   * @param [out] pathlabel - Retrieved lifetime
   * @return hICN error code
   */
  int (*get_lifetime) (hicn_type_t type, const hicn_protocol_t * h,
		       hicn_lifetime_t * lifetime);

  /**
   * @brief Sets an Interest or Data lifetime
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Interest or Data packet
   * @param [in] pathlabel - Lifetime to set
   * @return hICN error code
   */
  int (*set_lifetime) (hicn_type_t type, hicn_protocol_t * h,
		       const hicn_lifetime_t lifetime);

#if 0
  /**
   * @brief Update all checksums in packet headers
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the packet
   * @param [in] partial_csum - Partial checksum (set to 0, used internally to
   *   carry intermediate values from IP pseudo-header)
   * @param [in] payload_length - Payload length (can be set to 0, retrieved
   *   and used internally to carry payload length across protocol headers)
   * @return hICN error code
   */
  int (*update_checksums) (hicn_type_t type, hicn_protocol_t * h,
			   u16 partial_csum, size_t payload_length);

  /**
   * @brief Validate all checksums in packet headers
   * @param [in] type - hICN packet type
   * @param [in] h - Buffer holding the packet
   * @param [in] partial_csum - Partial checksum (set to 0, used internally to
   *   carry intermediate values from IP pseudo-header)
   * @param [in] payload_length - Payload length (can be set to 0, retrieved
   *   and used internally to carry payload length across protocol headers)
   * @return hICN error code
   */
  int (*verify_checksums) (hicn_type_t type, hicn_protocol_t * h,
			   u16 partial_csum, size_t payload_length);

#endif
  /**
   * @brief Rewrite an Interest packet header (locator)
   * @param [in] type - hICN packet type
   * @param [in] h - Buffer holding the Interest packet
   * @param [in] addr_new - New locator
   * @param [in] addr_old - Old locator (set to NULL, used internally to
   *   compute incremental checksums)
   * @return hICN error code
   */
  int (*rewrite_interest) (hicn_type_t type, hicn_protocol_t * h,
			   const ip46_address_t * addr_new,
			   ip46_address_t * addr_old);

  /**
   * @brief Rewrite a Data packet header (locator + pathlabel)
   * @param [in] type - hICN packet type
   * @param [in] h - Buffer holding the Data packet
   * @param [in] addr_new - New locator
   * @param [in] addr_old - Old locator (set to NULL, used internally to
   *   compute incremental checksums)
   * @param [in] face_id - Face identifier used to update pathlabel
   * @return hICN error code
   */
  int (*rewrite_data) (hicn_type_t type, hicn_protocol_t * h,
		       const ip46_address_t * addr_new,
		       ip46_address_t * addr_old,
		       const hicn_faceid_t face_id);

  /**
   * @brief Return the packet length
   * @param [in] type - hICN packet type
   * @param [in] h - Buffer holding the packet
   * @parma [out] length - Returned packet length
   * @return hICN error code
   */
  int (*get_length) (hicn_type_t type, const hicn_protocol_t * h,
		     size_t * length);

  /**
   * @brief Return the current packet header length
   * @param [in] type - hICN packet type
   * @param [in] h - Buffer holding the packet
   * @parma [out] header_length - Returned packet current header length
   * @return hICN error code
   */
  int (*get_current_header_length) (hicn_type_t type,
				    const hicn_protocol_t * h,
				    size_t * header_length);

  /**
   * @brief Return the packet header length
   * @param [in] type - hICN packet type
   * @param [in] h - Buffer holding the packet
   * @parma [out] header_length - Returned packet header length
   * @return hICN error code
   */
  int (*get_header_length) (hicn_type_t type, const hicn_protocol_t * h,
			    size_t * header_length);

  /**
   * @brief Return the packet payload length
   * @param [in] type - hICN packet type
   * @param [in] h - Buffer holding the packet
   * @parma [out] payload_length - Returned packet payload length
   * @return hICN error code
   */
  int (*get_payload_length) (hicn_type_t type, const hicn_protocol_t * h,
			     size_t * payload_length);

  /**
   * @brief Sets the packet paylaod length
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the packet
   * @parma [out] payload_length - Payload length to set
   * @return hICN error code
   */
  int (*set_payload_length) (hicn_type_t type, hicn_protocol_t * h,
			     size_t payload_length);

  /**
   * @brief Retrieves an Interest or Data signature size
   * @param [in] type - hICN packet type
   * @param [in] h - Buffer holding the Interest or Data packet
   * @param [out] signature_size - Retrieved signature size
   * @return hICN error code
   */
  int (*get_signature_size) (hicn_type_t type, const hicn_protocol_t * h,
			     size_t * signature_size);

  /**
   * @brief Sets an Interest or Data signature size
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Interest or Data packet
   * @param [in] signature_size - Signature size to set
   * @return hICN error code
   */
  int (*set_signature_size) (hicn_type_t type, hicn_protocol_t * h,
			     size_t signature_size);

  /**
   * @brief Gets the signature timestamp
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Interest or Data packet
   * @param [out] signature_timestamp - Retrieved signature timestamp
   * @return hICN error code
   */
  int (*get_signature_timestamp) (hicn_type_t type, const hicn_protocol_t * h,
                 uint64_t *signature_timestamp);

  /**
   * @brief Sets the signature timestamp
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Interest or Data packet
   * @param [in] signature_timestamp - Signature timestamp to set
   * @return hICN error code
   */
  int (*set_signature_timestamp) (hicn_type_t type, hicn_protocol_t * h,
                 uint64_t signature_timestamp);


  /**
   * @brief Gets the signature validation algorithm
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Interest or Data packet
   * @param [out] validation_algorithm - Retrieved validation_algorithm
   * @return hICN error code
   */
  int (*get_validation_algorithm) (hicn_type_t type, const hicn_protocol_t * h,
                 uint8_t *validation_algorithm);

  /**
   * @brief Sets the signature validation algorithm
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Interest or Data packet
   * @param [in] validation_algorithm - Validation algorithm enumeration
   * @return hICN error code
   */
  int (*set_validation_algorithm) (hicn_type_t type, hicn_protocol_t * h,
                 uint8_t validation_algorithm);


  /**
   * @brief Gets the key id
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Interest or Data packet
   * @param [out] key_id - Retrieved key id first byte address
   * @return hICN error code
   */
  int (*get_key_id) (hicn_type_t type, hicn_protocol_t * h,
                 uint8_t **key_id, uint8_t *key_id_size);

  /**
   * @brief Sets the key id
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Interest or Data packet
   * @param [in] key_id - Key id first byte address
   * @return hICN error code
   */
  int (*set_key_id) (hicn_type_t type, hicn_protocol_t * h,
                 uint8_t *key_id);

   /**
   * @brief Get a pointer to the signature field in the packet
   * @param [in] type - hICN packet type
   * @param [in,out] h - Buffer holding the Interest or Data packet
   * @param [out] signature - Pointer to the memory region holding the signature
   * @return hICN error code
   */
  int (*get_signature) (hicn_type_t type, hicn_protocol_t * h,
		              uint8_t ** signature);
} hicn_ops_t;

#define DECLARE_HICN_OPS(protocol)                                              \
  const hicn_ops_t hicn_ops_ ## protocol = {                                    \
    ATTR_INIT(init_packet_header,       protocol ## _init_packet_header),       \
    ATTR_INIT(get_interest_locator,     protocol ## _get_interest_locator),     \
    ATTR_INIT(set_interest_locator,     protocol ## _set_interest_locator),     \
    ATTR_INIT(get_interest_name,        protocol ## _get_interest_name),        \
    ATTR_INIT(set_interest_name,        protocol ## _set_interest_name),        \
    ATTR_INIT(get_interest_name_suffix, protocol ## _get_interest_name_suffix), \
    ATTR_INIT(set_interest_name_suffix, protocol ## _set_interest_name_suffix), \
    ATTR_INIT(reset_interest_for_hash,  protocol ## _reset_interest_for_hash),  \
    ATTR_INIT(get_data_locator,         protocol ## _get_data_locator),         \
    ATTR_INIT(set_data_locator,         protocol ## _set_data_locator),         \
    ATTR_INIT(get_data_name,            protocol ## _get_data_name),            \
    ATTR_INIT(set_data_name,            protocol ## _set_data_name),            \
    ATTR_INIT(get_data_name_suffix,     protocol ## _get_data_name_suffix),     \
    ATTR_INIT(set_data_name_suffix,     protocol ## _set_data_name_suffix),     \
    ATTR_INIT(get_data_pathlabel,       protocol ## _get_data_pathlabel),       \
    ATTR_INIT(set_data_pathlabel,       protocol ## _set_data_pathlabel),       \
    ATTR_INIT(update_data_pathlabel,    protocol ## _update_data_pathlabel),    \
    ATTR_INIT(reset_data_for_hash,      protocol ## _reset_data_for_hash),      \
    ATTR_INIT(get_lifetime,             protocol ## _get_lifetime),             \
    ATTR_INIT(set_lifetime,             protocol ## _set_lifetime),             \
    ATTR_INIT(rewrite_interest,         protocol ## _rewrite_interest),         \
    ATTR_INIT(rewrite_data,             protocol ## _rewrite_data),             \
    ATTR_INIT(get_length,               protocol ## _get_length),               \
    ATTR_INIT(get_current_header_length,protocol ## _get_current_header_length),\
    ATTR_INIT(get_header_length,        protocol ## _get_header_length),        \
    ATTR_INIT(get_payload_length,       protocol ## _get_payload_length),       \
    ATTR_INIT(set_payload_length,       protocol ## _set_payload_length),       \
    ATTR_INIT(get_signature_size,       protocol ## _get_signature_size),       \
    ATTR_INIT(set_signature_size,       protocol ## _set_signature_size),       \
    ATTR_INIT(get_signature_timestamp,  protocol ## _get_signature_timestamp),  \
    ATTR_INIT(set_signature_timestamp,  protocol ## _set_signature_timestamp),  \
    ATTR_INIT(get_validation_algorithm, protocol ## _get_validation_algorithm), \
    ATTR_INIT(set_validation_algorithm, protocol ## _set_validation_algorithm), \
    ATTR_INIT(get_key_id,               protocol ## _get_key_id),               \
    ATTR_INIT(set_key_id,               protocol ## _set_key_id),		        \
    ATTR_INIT(get_signature,            protocol ## _get_signature),		    \
  }

/**
 * @brief Protocol-independent packet operations VFT
 * NOTE: The following declarations should be kept in order
 */
extern const hicn_ops_t *const hicn_ops_vft[];

/*
 * Helpers for writing recursive protocol operations on packet headers
 *
 * NOTE : we cannot use a shift operation as IPPROTO_NONE != 0 (and 0 is IPv4...)
 */
always_inline hicn_type_t
TYPE_POP (hicn_type_t type)
{
#ifndef _WIN32
  return HICN_TYPE(type.l2, type.l3, type.l4, IPPROTO_NONE);
#else
  hicn_type_t new_type;
  new_type.l1 = type.l2;
  new_type.l2 = type.l3;
  new_type.l3 = type.l4;
  new_type.l4 = IPPROTO_NONE;
  return new_type;
#endif
}

always_inline hicn_protocol_t *
PAYLOAD (hicn_type_t type, const hicn_protocol_t * h)
{
  size_t header_length;
  int rc = hicn_ops_vft[type.l1]->get_current_header_length (type, h,
							     &header_length);
  if (rc < 0)
    return NULL;
  return (hicn_protocol_t *) ((u8 *) h + header_length);
}

#define CHILD_OPS(f, type, h, ...) (hicn_ops_vft[type.l2]->f(TYPE_POP(type), PAYLOAD(type, h), ## __VA_ARGS__))

/** Shortcuts to entry points in VFT */
#define HICN_OPS4 hicn_ops_vft[IPPROTO_IP]
#define HICN_OPS6 hicn_ops_vft[IPPROTO_IPV6]

/* Helpers for simple declarations */

#define DECLARE_init_packet_header(protocol, error) \
    int protocol ## _init_packet_header(hicn_type_t type, hicn_protocol_t * h) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_get_interest_locator(protocol, error) \
    int protocol ## _get_interest_locator(hicn_type_t type, const hicn_protocol_t * h, ip46_address_t * ip_address) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_set_interest_locator(protocol, error) \
    int protocol ## _set_interest_locator(hicn_type_t type, hicn_protocol_t * h, const ip46_address_t * ip_address) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_get_interest_name(protocol, error) \
    int protocol ## _get_interest_name(hicn_type_t type, const hicn_protocol_t * h, hicn_name_t * name) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_set_interest_name(protocol, error) \
    int protocol ## _set_interest_name(hicn_type_t type, hicn_protocol_t * h, const hicn_name_t * name) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_get_interest_name_suffix(protocol, error) \
    int protocol ## _get_interest_name_suffix(hicn_type_t type, const hicn_protocol_t * h, hicn_name_suffix_t * suffix) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_set_interest_name_suffix(protocol, error) \
    int protocol ## _set_interest_name_suffix(hicn_type_t type, hicn_protocol_t * h, const hicn_name_suffix_t * suffix) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_reset_interest_for_hash(protocol, error) \
    int protocol ## _reset_interest_for_hash(hicn_type_t type, hicn_protocol_t * h) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_get_data_locator(protocol, error) \
    int protocol ## _get_data_locator(hicn_type_t type, const hicn_protocol_t * h, ip46_address_t * ip_address) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_set_data_locator(protocol, error) \
    int protocol ## _set_data_locator(hicn_type_t type, hicn_protocol_t * h, const ip46_address_t * ip_address) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_get_data_name(protocol, error) \
    int protocol ## _get_data_name(hicn_type_t type, const hicn_protocol_t * h, hicn_name_t * name) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_set_data_name(protocol, error) \
    int protocol ## _set_data_name(hicn_type_t type, hicn_protocol_t * h, const hicn_name_t * name) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_get_data_name_suffix(protocol, error) \
    int protocol ## _get_data_name_suffix(hicn_type_t type, const hicn_protocol_t * h, hicn_name_suffix_t * suffix) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_set_data_name_suffix(protocol, error) \
    int protocol ## _set_data_name_suffix(hicn_type_t type, hicn_protocol_t * h, const hicn_name_suffix_t * suffix) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_get_data_pathlabel(protocol, error) \
    int protocol ## _get_data_pathlabel(hicn_type_t type, const hicn_protocol_t * h, u32 * pathlabel) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_set_data_pathlabel(protocol, error) \
    int protocol ## _set_data_pathlabel(hicn_type_t type, hicn_protocol_t * h, const u32 pathlabel) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_update_data_pathlabel(protocol, error) \
    int protocol ## _update_data_pathlabel(hicn_type_t type, hicn_protocol_t * h, const hicn_faceid_t face_id) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_reset_data_for_hash(protocol, error) \
    int protocol ## _reset_data_for_hash(hicn_type_t type, hicn_protocol_t * h) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_get_lifetime(protocol, error) \
    int protocol ## _get_lifetime(hicn_type_t type, const hicn_protocol_t * h, hicn_lifetime_t * lifetime) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_set_lifetime(protocol, error) \
    int protocol ## _set_lifetime(hicn_type_t type, hicn_protocol_t * h, const hicn_lifetime_t lifetime) { return HICN_LIB_ERROR_ ## error ; }

#if 0
#define DECLARE_update_checksums(protocol, error) \
    int protocol ## _update_checksums(hicn_type_t type, hicn_protocol_t * h, u16 partial_csum, size_t payload_length) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_verify_checksums(protocol, error) \
    int protocol ## _verify_checksums(hicn_type_t type, hicn_protocol_t * h, u16 partial_csum, size_t payload_length) { return HICN_LIB_ERROR_ ## error ; }
#endif

#define DECLARE_rewrite_interest(protocol, error) \
    int protocol ## _rewrite_interest(hicn_type_t type, hicn_protocol_t * h, const ip46_address_t * addr_new, ip46_address_t * addr_old) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_rewrite_data(protocol, error) \
    int protocol ## _rewrite_data(hicn_type_t type, hicn_protocol_t * h, const ip46_address_t * addr_new, ip46_address_t * addr_old, const hicn_faceid_t face_id) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_get_length(protocol, error) \
    int protocol ## _get_length(hicn_type_t type, const hicn_protocol_t * h, size_t * length) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_get_current_header_length(protocol, error) \
    int protocol ## _get_current_header_length(hicn_type_t type, const hicn_protocol_t * h, size_t * header_length) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_get_header_length(protocol, error) \
    int protocol ## _get_header_length(hicn_type_t type, const hicn_protocol_t * h, size_t * header_length) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_get_payload_length(protocol, error) \
    int protocol ## _get_payload_length(hicn_type_t type, const hicn_protocol_t * h, size_t * payload_length) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_set_payload_length(protocol, error) \
    int protocol ## _set_payload_length(hicn_type_t type, hicn_protocol_t * h, size_t payload_length) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_get_signature_size(protocol, error) \
    int protocol ## _get_signature_size(hicn_type_t type, const hicn_protocol_t * h, size_t * signature_size) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_set_signature_size(protocol, error) \
    int protocol ## _set_signature_size(hicn_type_t type, hicn_protocol_t * h, size_t signature_size) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_set_signature_timestamp(protocol, error) \
    int protocol ## _set_signature_timestamp(hicn_type_t type, hicn_protocol_t * h, uint64_t signature_timestamp) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_get_signature_timestamp(protocol, error) \
    int protocol ## _get_signature_timestamp(hicn_type_t type, const hicn_protocol_t * h, uint64_t * signature_timestamp) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_set_validation_algorithm(protocol, error) \
    int protocol ## _set_validation_algorithm(hicn_type_t type, hicn_protocol_t * h, uint8_t validation_algorithm) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_get_validation_algorithm(protocol, error) \
    int protocol ## _get_validation_algorithm(hicn_type_t type, const hicn_protocol_t * h, uint8_t * validation_algorithm) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_set_key_id(protocol, error) \
    int protocol ## _set_key_id(hicn_type_t type, hicn_protocol_t * h, uint8_t * key_id) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_get_key_id(protocol, error) \
    int protocol ## _get_key_id(hicn_type_t type, hicn_protocol_t * h, uint8_t ** key_id, uint8_t *key_id_size) { return HICN_LIB_ERROR_ ## error ; }

#define DECLARE_get_signature(protocol, error) \
    int protocol ## _get_signature(hicn_type_t type, hicn_protocol_t * h, uint8_t ** signature) { return HICN_LIB_ERROR_ ## error ; }

#endif /* HICN_OPS_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
