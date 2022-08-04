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
 * @file base.h
 * @brief Protocol-independent packet operations
 */

#ifndef HICN_OPS_H
#define HICN_OPS_H

#include <assert.h>
#include <stdlib.h>

#include <hicn/base.h>
#include <hicn/error.h>
#include <hicn/name.h>
#include <hicn/packet.h> // HICN_OPAQUE_LEN
#include <hicn/util/ip_address.h>

#include "protocol.h"

/*
 * In order to provide fast lookup and accelerate packet operations, we allow
 * ourselves to use a header cache structure under the responsibility of the
 * caller, and that can be associated to each packet. This structure is exposed
 * as a opaque pointer.
 */

/*
 * hICN operations on packets
 *
 * All prototypes take an hicn_type_t parameter as their first argument, as
 * this decides the sequence of protocols that are being used by the different
 * operations.
 */

typedef struct hicn_ops_s
{
  const char *name;

  size_t header_len;

  /**
   * @brief Initialize the headers of the hicn packet
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   */
  int (*init_packet_header) (hicn_packet_buffer_t *pkbuf, size_t pos);

  /**
   * @brief Retrieves an Interest locator
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [out] ip_address - Retrieved locator
   * @return hICN error code
   */
  int (*get_interest_locator) (const hicn_packet_buffer_t *pkbuf,
			       const size_t pos,
			       hicn_ip_address_t *ip_address);

  /**
   * @brief Sets an Interest locator
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [in] ip_address - Locator to set
   * @return hICN error code
   */
  int (*set_interest_locator) (const hicn_packet_buffer_t *pkbuf, size_t pos,
			       const hicn_ip_address_t *ip_address);

  /**
   * @brief Retrieves an Interest name
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [out] name - Retrieved name
   * @return hICN error code
   */
  int (*get_interest_name) (const hicn_packet_buffer_t *pkbuf,
			    const size_t pos, hicn_name_t *name);

  /**
   * @brief Sets an Interest name
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [in] name - Name to set
   * @return hICN error code
   */
  int (*set_interest_name) (const hicn_packet_buffer_t *pkbuf, size_t pos,
			    const hicn_name_t *name);

  /**
   * @brief Retrieves an Interest name suffix
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [out] suffix - Retrieved name suffix
   * @return hICN error code
   */
  int (*get_interest_name_suffix) (const hicn_packet_buffer_t *pkbuf,
				   const size_t pos,
				   hicn_name_suffix_t *suffix);

  /**
   * @brief Sets an Interest name suffix
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [in] suffix - Name suffix to set
   * @return hICN error code
   */
  int (*set_interest_name_suffix) (const hicn_packet_buffer_t *pkbuf,
				   size_t pos,
				   const hicn_name_suffix_t *suffix);

  /**
   * @brief Get packet type
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Position within the network layers
   * @param [out] type - Packet type
   * @return hICN error code
   */
  int (*get_type) (const hicn_packet_buffer_t *pkbuf, const size_t pos,
		   hicn_packet_type_t *type);

  /**
   * @brief Set flag to mark current packet as interest
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Position within the network layers
   * @param [in] type - Packet type
   * @return hICN error code
   */
  int (*set_type) (const hicn_packet_buffer_t *pkbuf, size_t pos,
		   hicn_packet_type_t type);

  /**
   * @brief Clear the necessary Interest fields in order to hash it
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @return hICN error code
   */
  int (*reset_interest_for_hash) (hicn_packet_buffer_t *pkbuf, size_t pos);

  /**
   * @brief Retrieves a Data locator
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [out] ip_address - Retrieved locator
   * @return hICN error code
   */
  int (*get_data_locator) (const hicn_packet_buffer_t *pkbuf, const size_t pos,
			   hicn_ip_address_t *ip_address);

  /**
   * @brief Sets a Data locator
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [in] ip_address - Locator to set
   * @return hICN error code
   */
  int (*set_data_locator) (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   const hicn_ip_address_t *ip_address);

  /**
   * @brief Retrieves a Data name
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [out] name - Retrieved name
   * @return hICN error code
   */
  int (*get_data_name) (const hicn_packet_buffer_t *pkbuf, const size_t pos,
			hicn_name_t *name);

  /**
   * @brief Sets a Data name
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [in] name - Name to set
   * @return hICN error code
   */
  int (*set_data_name) (const hicn_packet_buffer_t *pkbuf, size_t pos,
			const hicn_name_t *name);

  /**
   * @brief Retrieves a Data name suffix
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [out] suffix - Retrieved name suffix
   * @return hICN error code
   */
  int (*get_data_name_suffix) (const hicn_packet_buffer_t *pkbuf,
			       const size_t pos, hicn_name_suffix_t *suffix);

  /**
   * @brief Sets a Data name suffix
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [in] suffix - Name suffix to set
   * @return hICN error code
   */
  int (*set_data_name_suffix) (const hicn_packet_buffer_t *pkbuf, size_t pos,
			       const hicn_name_suffix_t *suffix);

  /**
   * @brief Retrieves a Data path_label
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [out] path_label - Retrieved path_label
   * @return hICN error code
   */
  int (*get_data_path_label) (const hicn_packet_buffer_t *pkbuf,
			      const size_t pos, hicn_path_label_t *path_label);

  /**
   * @brief Sets a Data path_label
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [in] path_label - Pathlabel to set
   * @return hICN error code
   */
  int (*set_data_path_label) (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      const hicn_path_label_t path_label);

  /**
   * @brief Update a Data path_label with a new face identifier
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [in] path_label - Face identifier used to update path_label
   * @return hICN error code
   */
  int (*update_data_path_label) (const hicn_packet_buffer_t *pkbuf, size_t pos,
				 const hicn_faceid_t face_id);

  /**
   * @brief Clear the necessary Data fields in order to hash it
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @return hICN error code
   */
  int (*reset_data_for_hash) (hicn_packet_buffer_t *pkbuf, size_t pos);

  /**
   * @brief Retrieves an Interest or Data lifetime
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Current position in the sequence of headers while
   * executing command
   * @param [out] path_label - Retrieved lifetime
   * @return hICN error code
   */
  int (*get_lifetime) (const hicn_packet_buffer_t *pkbuf, const size_t pos,
		       hicn_lifetime_t *lifetime);

  /**
   * @brief Sets an Interest or Data lifetime
   * @param [in] pkbuf - hICN packet buffer
   * @param [in,out] pos - Current position in the sequence of headers while
   * executing command
   * @param [in] path_label - Lifetime to set
   * @return hICN error code
   */
  int (*set_lifetime) (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       const hicn_lifetime_t lifetime);

  /**
   * @brief Update all checksums in packet headers
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [in] partial_csum - Partial checksum (set to 0, used internally to
   *   carry intermediate values from IP pseudo-header)
   * @param [in] payload_len - Payload len (can be set to ~0, retrieved
   *   and used internally to carry payload len across protocol headers)
   * @return hICN error code
   *
   * Payload len is initialized during the initial steps (eg. IP) if not
   * provided (value is ~0), and not ignored (value is 0).
   */
  int (*update_checksums) (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   u16 partial_csum, size_t payload_len);

  /**
   * @brief Update all checksums in packet headers
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [in] old_val - Pointer to the old value
   * @param [in] new_val - Pointer to the new value
   * @param [in] size - Size of the changed value
   * @param [in] skip_first - Skip the first protocol (ignore IP checksum)
   * @return hICN error code
   */
  int (*update_checksums_incremental) (const hicn_packet_buffer_t *pkbuf,
				       size_t pos, u16 *old_val, u16 *new_val,
				       u8 size, bool skip_first);

  /**
   * @brief Validate all checksums in packet headers
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [in] partial_csum - Partial checksum, or zero if no partial
   * checksum available
   * @param [in] payload_len - Payload len (can be set to ~0, retrieved
   *   and used internally to carry payload len across protocol headers)
   * @return hICN error code
   */
  int (*verify_checksums) (const hicn_packet_buffer_t *pkbuf, const size_t pos,
			   u16 partial_csum, size_t payload_len);

  /**
   * @brief Rewrite an Interest packet header (locator)
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [in] addr_new - New locator
   * @param [in] addr_old - Old locator (set to NULL, used internally to
   *   compute incremental checksums)
   * @return hICN error code
   */
  int (*rewrite_interest) (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   const hicn_ip_address_t *addr_new,
			   hicn_ip_address_t *addr_old);

  /**
   * @brief Rewrite a Data packet header (locator + path_label)
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @param [in] addr_new - New locator
   * @param [in] addr_old - Old locator (set to NULL, used internally to
   *   compute incremental checksums)
   * @param [in] face_id - Face identifier used to update path_label
   * @param [in] reset_pl - If not zero, reset the current path_label
   *   before update it
   * @return hICN error code
   */
  int (*rewrite_data) (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       const hicn_ip_address_t *addr_new,
		       hicn_ip_address_t *addr_old,
		       const hicn_faceid_t face_id, u8 reset_pl);

  /**
   * @brief Return the packet len
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @parma [out] len - Returned packet len
   * @return hICN error code
   */
  int (*get_len) (const hicn_packet_buffer_t *pkbuf, const size_t pos,
		  size_t *len);

  /**
   * @brief Return the current packet header len
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @parma [out] header_len - Returned packet current header len
   * @return hICN error code
   */
  int (*get_current_header_len) (const hicn_packet_buffer_t *pkbuf,
				 const size_t pos, size_t *header_len);

  /**
   * @brief Sets the packet paylaod len
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Depth in the header stack
   * @parma [out] payload_len - Payload len to set
   * @return hICN error code
   */
  int (*set_payload_len) (const hicn_packet_buffer_t *pkbuf, size_t pos,
			  size_t payload_len);

  /**
   * @brief Retrieves an Interest or Data signature size
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Current position in the sequence of headers while
   * executing command
   * @param [out] signature_size - Retrieved signature size
   * @return hICN error code
   */
  int (*get_signature_size) (const hicn_packet_buffer_t *pkbuf,
			     const size_t pos, size_t *signature_size);

  /**
   * @brief Sets an Interest or Data signature size
   * @param [in] pkbuf - hICN packet buffer
   * @param [in,out] pos - Current position in the sequence of headers while
   * executing command
   * @param [in] signature_size - Signature size to set
   * @return hICN error code
   */
  int (*set_signature_size) (const hicn_packet_buffer_t *pkbuf, size_t pos,
			     size_t signature_size);

  /**
   * @brief Sets an Interest or Data signature padding between maximum size and
   * real size
   * @param [in] pkbuf - hICN packet buffer
   * @param [in,out] pos - Current position in the sequence of headers while
   * executing command
   * @param [in] signature_size - Signature size to set
   * @return hICN error code
   */
  int (*set_signature_padding) (const hicn_packet_buffer_t *pkbuf, size_t pos,
				size_t signature_padding);

  /**
   * @brief gets an Interest or Data signature padding between maximum size and
   * real size
   * @param [in] pkbuf - hICN packet buffer
   * @param [in,out] pos - Current position in the sequence of headers while
   * executing command
   * @param [in] signature_size - retrieve the padding between maximum size and
   * real size
   * @return hICN error code
   */
  int (*get_signature_padding) (const hicn_packet_buffer_t *pkbuf,
				const size_t pos, size_t *signature_padding);

  /**
   * @brief Gets the signature timestamp
   * @param [in] pkbuf - hICN packet buffer
   * @param [in,out] pos - Current position in the sequence of headers while
   * executing command
   * @param [out] signature_timestamp - Retrieved signature timestamp
   * @return hICN error code
   */
  int (*get_signature_timestamp) (const hicn_packet_buffer_t *pkbuf,
				  const size_t pos,
				  uint64_t *signature_timestamp);

  /**
   * @brief Sets the signature timestamp
   * @param [in] pkbuf - hICN packet buffer
   * @param [in,out] pos - Current position in the sequence of headers while
   * executing command
   * @param [in] signature_timestamp - Signature timestamp to set
   * @return hICN error code
   */
  int (*set_signature_timestamp) (const hicn_packet_buffer_t *pkbuf,
				  size_t pos, uint64_t signature_timestamp);

  /**
   * @brief Gets the signature validation algorithm
   * @param [in] pkbuf - hICN packet buffer
   * @param [in,out] pos - Current position in the sequence of headers while
   * executing command
   * @param [out] validation_algorithm - Retrieved validation_algorithm
   * @return hICN error code
   */
  int (*get_validation_algorithm) (const hicn_packet_buffer_t *pkbuf,
				   const size_t pos,
				   uint8_t *validation_algorithm);

  /**
   * @brief Sets the signature validation algorithm
   * @param [in] pkbuf - hICN packet buffer
   * @param [in,out] pos - Current position in the sequence of headers while
   * executing command
   * @param [in] validation_algorithm - Validation algorithm enumeration
   * @return hICN error code
   */
  int (*set_validation_algorithm) (const hicn_packet_buffer_t *pkbuf,
				   size_t pos, uint8_t validation_algorithm);

  /**
   * @brief Gets the key id
   * @param [in] pkbuf - hICN packet buffer
   * @param [in,out] pos - Current position in the sequence of headers while
   * executing command
   * @param [out] key_id - Retrieved key id first byte address
   * @return hICN error code
   */
  int (*get_key_id) (const hicn_packet_buffer_t *pkbuf, const size_t pos,
		     uint8_t **key_id, uint8_t *key_id_size);

  /**
   * @brief Sets the key id
   * @param [in] pkbuf - hICN packet buffer
   * @param [in,out] pos - Current position in the sequence of headers while
   * executing command
   * @param [in] key_id - Key id first byte address
   * @return hICN error code
   */
  int (*set_key_id) (const hicn_packet_buffer_t *pkbuf, size_t pos,
		     uint8_t *key_id, size_t size);

  /**
   * @brief Get a pointer to the signature field in the packet
   * @param [in] pkbuf - hICN packet buffer
   * @param [in,out] pos - Current position in the sequence of headers while
   * executing command
   * @param [out] signature - Pointer to the memory region holding the
   * signature
   * @return hICN error code
   */
  int (*get_signature) (const hicn_packet_buffer_t *pkbuf, const size_t pos,
			uint8_t **signature);

  /**
   * @brief Returns whether the packet holds a signature.
   * @param [in] pkbuf - hICN packet buffer
   * @param [in,out] pos - Current position in the sequence of headers while
   * executing command
   * @param [out] flag - Boolean indicating whether the packet has a signature.
   * @return hICN error code
   */
  int (*has_signature) (const hicn_packet_buffer_t *pkbuf, const size_t pos,
			bool *flag);

  /**
   * @brief Set payload type of the packet
   * @param [in] pkbuf - hICN packet buffer
   * @param [in,out] pos - Current position in the sequence of headers while
   * executing command
   * @param [in] payload_type - The payload type of this packet
   * @return hICN error code
   */
  int (*set_payload_type) (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   hicn_payload_type_t payload_type);

  /**
   * @brief Get payload type from the packet
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Current position in the sequence of headers while
   * executing command
   * @param [out] payload_type - The payload type of this packet
   * @return hICN error code
   */
  int (*get_payload_type) (const hicn_packet_buffer_t *pkbuf, const size_t pos,
			   hicn_payload_type_t *payload_type);

  /**
   * @brief Check if data packet is last one.
   * @param [in] pkbuf - hICN packet buffer
   * @param [in] pos - Current position in the sequence of headers while
   * executing command
   * @param [out] is_last - 1 if last data, 0 otherwise
   * @return hICN error code
   */
  int (*is_last_data) (const hicn_packet_buffer_t *pkbuf, const size_t pos,
		       int *is_last);

  /**
   * @brief Mark data packet as last
   * @param [in] pkbuf - hICN packet buffer
   * @param [in, out] pos - Current position in the sequence of headers while
   * executing command
   * @return hICN error code
   */
  int (*set_last_data) (const hicn_packet_buffer_t *pkbuf, size_t pos);

  /**
   * @brief Returns the packet TTL
   * @param [in] pkbuf - hICN packet buffer
   * @param [in, out] pos - Current position in the sequence of headers while
   * @param [out] hops - Pointer to the variable receiving the TTL value
   * @return hICN error code
   */
  int (*get_ttl) (const hicn_packet_buffer_t *pkbuf, size_t pos, u8 *hops);

  /**
   * @brief Returns the packet source port
   * @param [in] pkbuf - hICN packet buffer
   * @param [in, out] pos - Current position in the sequence of headers while
   * @param [out] hops - The TTL value to set
   * @return hICN error code
   */
  int (*set_ttl) (const hicn_packet_buffer_t *pkbuf, size_t pos, u8 hops);

  /**
   * @brief Returns the packet source port
   * @param [in] pkbuf - hICN packet buffer
   * @param [in, out] pos - Current position in the sequence of headers while
   * @param [out] port - Pointer to the variable that will receive the port
   * number
   * @return hICN error code
   */
  int (*get_src_port) (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       u16 *port);

  /**
   * @brief Sets the packet source port
   * @param [in] pkbuf - hICN packet buffer
   * @param [in, out] pos - Current position in the sequence of headers while
   * @param [out] port - The port number to set
   * @return hICN error code
   */
  int (*set_src_port) (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       u16 port);

  /**
   * @brief Returns the packet source port
   * @param [in] pkbuf - hICN packet buffer
   * @param [in, out] pos - Current position in the sequence of headers while
   * @param [out] port - Pointer to the variable that will receive the port
   * number
   * @return hICN error code
   */
  int (*get_dst_port) (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       u16 *port);

  /**
   * @brief Sets the packet source port
   * @param [in] pkbuf - hICN packet buffer
   * @param [in, out] pos - Current position in the sequence of headers while
   * @param [out] port - The port number to set
   * @return hICN error code
   */
  int (*set_dst_port) (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       u16 port);
} hicn_ops_t;

#define DECLARE_HICN_OPS(protocol, len)                                       \
  const hicn_ops_t hicn_ops_##protocol = {                                    \
    ATTR_INIT (name, #protocol),                                              \
    ATTR_INIT (header_len, len),                                              \
    ATTR_INIT (init_packet_header, protocol##_init_packet_header),            \
    ATTR_INIT (get_interest_locator, protocol##_get_interest_locator),        \
    ATTR_INIT (set_interest_locator, protocol##_set_interest_locator),        \
    ATTR_INIT (get_interest_name, protocol##_get_interest_name),              \
    ATTR_INIT (set_interest_name, protocol##_set_interest_name),              \
    ATTR_INIT (get_interest_name_suffix,                                      \
	       protocol##_get_interest_name_suffix),                          \
    ATTR_INIT (set_interest_name_suffix,                                      \
	       protocol##_set_interest_name_suffix),                          \
    ATTR_INIT (get_type, protocol##_get_type),                                \
    ATTR_INIT (set_type, protocol##_set_type),                                \
    ATTR_INIT (reset_interest_for_hash, protocol##_reset_interest_for_hash),  \
    ATTR_INIT (get_data_locator, protocol##_get_data_locator),                \
    ATTR_INIT (set_data_locator, protocol##_set_data_locator),                \
    ATTR_INIT (get_data_name, protocol##_get_data_name),                      \
    ATTR_INIT (set_data_name, protocol##_set_data_name),                      \
    ATTR_INIT (get_data_name_suffix, protocol##_get_data_name_suffix),        \
    ATTR_INIT (set_data_name_suffix, protocol##_set_data_name_suffix),        \
    ATTR_INIT (get_data_path_label, protocol##_get_data_path_label),          \
    ATTR_INIT (set_data_path_label, protocol##_set_data_path_label),          \
    ATTR_INIT (update_data_path_label, protocol##_update_data_path_label),    \
    ATTR_INIT (reset_data_for_hash, protocol##_reset_data_for_hash),          \
    ATTR_INIT (get_lifetime, protocol##_get_lifetime),                        \
    ATTR_INIT (set_lifetime, protocol##_set_lifetime),                        \
    ATTR_INIT (update_checksums, protocol##_update_checksums),                \
    ATTR_INIT (update_checksums_incremental,                                  \
	       protocol##_update_checksums_incremental),                      \
    ATTR_INIT (verify_checksums, protocol##_verify_checksums),                \
    ATTR_INIT (rewrite_interest, protocol##_rewrite_interest),                \
    ATTR_INIT (rewrite_data, protocol##_rewrite_data),                        \
    ATTR_INIT (set_payload_len, protocol##_set_payload_len),                  \
    ATTR_INIT (get_payload_type, protocol##_get_payload_type),                \
    ATTR_INIT (set_payload_type, protocol##_set_payload_type),                \
    ATTR_INIT (get_signature_size, protocol##_get_signature_size),            \
    ATTR_INIT (get_signature_timestamp, protocol##_get_signature_timestamp),  \
    ATTR_INIT (set_signature_timestamp, protocol##_set_signature_timestamp),  \
    ATTR_INIT (get_validation_algorithm,                                      \
	       protocol##_get_validation_algorithm),                          \
    ATTR_INIT (set_validation_algorithm,                                      \
	       protocol##_set_validation_algorithm),                          \
    ATTR_INIT (get_key_id, protocol##_get_key_id),                            \
    ATTR_INIT (set_key_id, protocol##_set_key_id),                            \
    ATTR_INIT (get_signature, protocol##_get_signature),                      \
    ATTR_INIT (has_signature, protocol##_has_signature),                      \
    ATTR_INIT (set_signature_padding, protocol##_set_signature_padding),      \
    ATTR_INIT (set_signature_size, protocol##_set_signature_size),            \
    ATTR_INIT (get_signature_padding, protocol##_get_signature_padding),      \
    ATTR_INIT (is_last_data, protocol##_is_last_data),                        \
    ATTR_INIT (get_ttl, protocol##_get_ttl),                                  \
    ATTR_INIT (set_ttl, protocol##_set_ttl),                                  \
    ATTR_INIT (get_src_port, protocol##_get_src_port),                        \
    ATTR_INIT (set_src_port, protocol##_set_src_port),                        \
    ATTR_INIT (get_dst_port, protocol##_get_dst_port),                        \
    ATTR_INIT (set_dst_port, protocol##_set_dst_port),                        \
  }

/**
 * @brief Protocol-independent packet operations VFT
 * NOTE: The following declarations should be kept in order
 */
extern const hicn_ops_t *const hicn_ops_vft[];

#define PROT(pkbuf, pos)                                                      \
  ((pos < (HICN_FORMAT_LEN - 1)) ?                                            \
	   hicn_packet_get_format (pkbuf).as_u8[(pos) + 1] :                        \
	   IPPROTO_NONE)

#define CALL_CHILD(method, pkbuf, pos, ...)                                   \
  hicn_ops_vft[PROT (pkbuf, (pos))]->method (pkbuf, (pos) + 1, ##__VA_ARGS__);

#define CALL(method, pkbuf, ...) CALL_CHILD (method, pkbuf, -1, ##__VA_ARGS__)

/** Shortcuts to entry points in VFT */
#define HICN_OPS4 hicn_ops_vft[IPPROTO_IP]
#define HICN_OPS6 hicn_ops_vft[IPPROTO_IPV6]

/* Helpers for simple declarations */

#define DECLARE_init_packet_header(protocol, error)                           \
  int protocol##_init_packet_header (hicn_packet_buffer_t *pkbuf, size_t pos) \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_interest_locator(protocol, error)                         \
  int protocol##_get_interest_locator (const hicn_packet_buffer_t *pkbuf,     \
				       const size_t pos,                      \
				       hicn_ip_address_t *ip_address)         \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_interest_locator(protocol, error)                         \
  int protocol##_set_interest_locator (const hicn_packet_buffer_t *pkbuf,     \
				       size_t pos,                            \
				       const hicn_ip_address_t *ip_address)   \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_interest_name(protocol, error)                            \
  int protocol##_get_interest_name (const hicn_packet_buffer_t *pkbuf,        \
				    const size_t pos, hicn_name_t *name)      \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_interest_name(protocol, error)                            \
  int protocol##_set_interest_name (const hicn_packet_buffer_t *pkbuf,        \
				    size_t pos, const hicn_name_t *name)      \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_interest_name_suffix(protocol, error)                     \
  int protocol##_get_interest_name_suffix (const hicn_packet_buffer_t *pkbuf, \
					   const size_t pos,                  \
					   hicn_name_suffix_t *suffix)        \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_interest_name_suffix(protocol, error)                     \
  int protocol##_set_interest_name_suffix (const hicn_packet_buffer_t *pkbuf, \
					   size_t pos,                        \
					   const hicn_name_suffix_t *suffix)  \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_type(protocol, error)                                     \
  int protocol##_get_type (const hicn_packet_buffer_t *pkbuf,                 \
			   const size_t pos, hicn_packet_type_t *type)        \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_type(protocol, error)                                     \
  int protocol##_set_type (const hicn_packet_buffer_t *pkbuf,                 \
			   const size_t pos, hicn_packet_type_t type)         \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_reset_interest_for_hash(protocol, error)                      \
  int protocol##_reset_interest_for_hash (hicn_packet_buffer_t *pkbuf,        \
					  size_t pos)                         \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_data_locator(protocol, error)                             \
  int protocol##_get_data_locator (const hicn_packet_buffer_t *pkbuf,         \
				   const size_t pos,                          \
				   hicn_ip_address_t *ip_address)             \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_data_locator(protocol, error)                             \
  int protocol##_set_data_locator (const hicn_packet_buffer_t *pkbuf,         \
				   size_t pos,                                \
				   const hicn_ip_address_t *ip_address)       \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_data_name(protocol, error)                                \
  int protocol##_get_data_name (const hicn_packet_buffer_t *pkbuf,            \
				const size_t pos, hicn_name_t *name)          \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_data_name(protocol, error)                                \
  int protocol##_set_data_name (const hicn_packet_buffer_t *pkbuf,            \
				size_t pos, const hicn_name_t *name)          \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_data_name_suffix(protocol, error)                         \
  int protocol##_get_data_name_suffix (const hicn_packet_buffer_t *pkbuf,     \
				       const size_t pos,                      \
				       hicn_name_suffix_t *suffix)            \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_data_name_suffix(protocol, error)                         \
  int protocol##_set_data_name_suffix (const hicn_packet_buffer_t *pkbuf,     \
				       size_t pos,                            \
				       const hicn_name_suffix_t *suffix)      \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_data_path_label(protocol, error)                          \
  int protocol##_get_data_path_label (const hicn_packet_buffer_t *pkbuf,      \
				      const size_t pos,                       \
				      hicn_path_label_t *path_label)          \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_data_path_label(protocol, error)                          \
  int protocol##_set_data_path_label (const hicn_packet_buffer_t *pkbuf,      \
				      size_t pos,                             \
				      const hicn_path_label_t path_label)     \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_update_data_path_label(protocol, error)                       \
  int protocol##_update_data_path_label (const hicn_packet_buffer_t *pkbuf,   \
					 size_t pos,                          \
					 const hicn_faceid_t face_id)         \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_reset_data_for_hash(protocol, error)                          \
  int protocol##_reset_data_for_hash (hicn_packet_buffer_t *pkbuf,            \
				      size_t pos)                             \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_lifetime(protocol, error)                                 \
  int protocol##_get_lifetime (const hicn_packet_buffer_t *pkbuf,             \
			       const size_t pos, hicn_lifetime_t *lifetime)   \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_lifetime(protocol, error)                                 \
  int protocol##_set_lifetime (const hicn_packet_buffer_t *pkbuf, size_t pos, \
			       const hicn_lifetime_t lifetime)                \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_update_checksums(protocol, error)                             \
  int protocol##_update_checksums (const hicn_packet_buffer_t *pkbuf,         \
				   size_t pos, u16 partial_csum,              \
				   size_t payload_len)                        \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_update_checksums_incremental(protocol, error)                 \
  int protocol##_update_checksums_incremental (                               \
    const hicn_packet_buffer_t *pkbuf, size_t pos, u16 *old_val,              \
    u16 *new_val, u8 size, bool skip_first)                                   \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_verify_checksums(protocol, error)                             \
  int protocol##_verify_checksums (const hicn_packet_buffer_t *pkbuf,         \
				   const size_t pos, u16 partial_csum,        \
				   size_t payload_len)                        \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_rewrite_interest(protocol, error)                             \
  int protocol##_rewrite_interest (                                           \
    const hicn_packet_buffer_t *pkbuf, size_t pos,                            \
    const hicn_ip_address_t *addr_new, hicn_ip_address_t *addr_old)           \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_rewrite_data(protocol, error)                                 \
  int protocol##_rewrite_data (const hicn_packet_buffer_t *pkbuf, size_t pos, \
			       const hicn_ip_address_t *addr_new,             \
			       hicn_ip_address_t *addr_old,                   \
			       const hicn_faceid_t face_id, u8 reset_pl)      \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_payload_len(protocol, error)                              \
  int protocol##_set_payload_len (const hicn_packet_buffer_t *pkbuf,          \
				  size_t pos, size_t payload_len)             \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_payload_type(protocol, error)                             \
  int protocol##_get_payload_type (const hicn_packet_buffer_t *pkbuf,         \
				   const size_t pos,                          \
				   hicn_payload_type_t *payload_type)         \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_payload_type(protocol, error)                             \
  int protocol##_set_payload_type (const hicn_packet_buffer_t *pkbuf,         \
				   size_t pos,                                \
				   hicn_payload_type_t payload_type)          \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_signature_size(protocol, error)                           \
  int protocol##_get_signature_size (const hicn_packet_buffer_t *pkbuf,       \
				     const size_t pos,                        \
				     size_t *signature_size)                  \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_signature_size(protocol, error)                           \
  int protocol##_set_signature_size (const hicn_packet_buffer_t *pkbuf,       \
				     size_t pos, size_t signature_size)       \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_signature_padding(protocol, error)                        \
  int protocol##_set_signature_padding (const hicn_packet_buffer_t *pkbuf,    \
					size_t pos, size_t padding)           \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_signature_padding(protocol, error)                        \
  int protocol##_get_signature_padding (const hicn_packet_buffer_t *pkbuf,    \
					const size_t pos, size_t *padding)    \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_signature_timestamp(protocol, error)                      \
  int protocol##_set_signature_timestamp (const hicn_packet_buffer_t *pkbuf,  \
					  size_t pos,                         \
					  uint64_t signature_timestamp)       \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_signature_timestamp(protocol, error)                      \
  int protocol##_get_signature_timestamp (const hicn_packet_buffer_t *pkbuf,  \
					  const size_t pos,                   \
					  uint64_t *signature_timestamp)      \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_validation_algorithm(protocol, error)                     \
  int protocol##_set_validation_algorithm (const hicn_packet_buffer_t *pkbuf, \
					   size_t pos,                        \
					   uint8_t validation_algorithm)      \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_validation_algorithm(protocol, error)                     \
  int protocol##_get_validation_algorithm (const hicn_packet_buffer_t *pkbuf, \
					   const size_t pos,                  \
					   uint8_t *validation_algorithm)     \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_key_id(protocol, error)                                   \
  int protocol##_set_key_id (const hicn_packet_buffer_t *pkbuf, size_t pos,   \
			     uint8_t *key_id, size_t size)                    \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_key_id(protocol, error)                                   \
  int protocol##_get_key_id (const hicn_packet_buffer_t *pkbuf,               \
			     const size_t pos, uint8_t **key_id,              \
			     uint8_t *key_id_size)                            \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_signature(protocol, error)                                \
  int protocol##_get_signature (const hicn_packet_buffer_t *pkbuf,            \
				const size_t pos, uint8_t **signature)        \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_has_signature(protocol, error)                                \
  int protocol##_has_signature (const hicn_packet_buffer_t *pkbuf,            \
				const size_t pos, bool *flag)                 \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_is_last_data(protocol, error)                                 \
  int protocol##_is_last_data (const hicn_packet_buffer_t *pkbuf,             \
			       const size_t pos, int *is_last)                \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_last_data(protocol, error)                                \
  int protocol##_set_last_data (const hicn_packet_buffer_t *pkbuf,            \
				size_t pos)                                   \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_ttl(protocol, error)                                      \
  int protocol##_get_ttl (const hicn_packet_buffer_t *pkbuf, size_t pos,      \
			  u8 *hops)                                           \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_ttl(protocol, error)                                      \
  int protocol##_set_ttl (const hicn_packet_buffer_t *pkbuf, size_t pos,      \
			  u8 hops)                                            \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_src_port(protocol, error)                                 \
  int protocol##_get_src_port (const hicn_packet_buffer_t *pkbuf, size_t pos, \
			       u16 *port)                                     \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_src_port(protocol, error)                                 \
  int protocol##_set_src_port (const hicn_packet_buffer_t *pkbuf, size_t pos, \
			       u16 port)                                      \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_get_dst_port(protocol, error)                                 \
  int protocol##_get_dst_port (const hicn_packet_buffer_t *pkbuf, size_t pos, \
			       u16 *port)                                     \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#define DECLARE_set_dst_port(protocol, error)                                 \
  int protocol##_set_dst_port (const hicn_packet_buffer_t *pkbuf, size_t pos, \
			       u16 port)                                      \
  {                                                                           \
    return HICN_LIB_ERROR_##error;                                            \
  }

#endif /* HICN_OPS_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
