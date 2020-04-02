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
 * @file compat.h
 * @brief Implementation of the compatibility layer.
 *
 * The structure of the core API has evolved to support operations of a variety
 * of packet formats in addition to IPv4/TCP and IPv6/TCP, namely with the use
 * of ICMP for signalization and AH headers for integrity. The new API format
 * has been designed to scale better with the multiplicity of packet formats,
 * and provide a unified interface on top. We maintain an interface for the
 * former API in this file, which mainly acts as a wrapper on top of new calls.
 */
#ifndef HICN_COMPAT_H
#define HICN_COMPAT_H

#include "common.h"
#include "header.h"
#include "name.h"

/* HICN format options */
#define HFO_INET  1 << 0
#define HFO_INET6 1 << 1
#define HFO_TCP   1 << 2
#define HFO_ICMP  1 << 3
#define HFO_AH    1 << 4

#define _is_ipv4(format) ((format & HFO_INET))
#define _is_ipv6(format) ((format & HFO_INET6) >> 1)
#define _is_tcp(format)  ((format & HFO_TCP)   >> 2)
#define _is_icmp(format) ((format & HFO_ICMP)  >> 3)
#define _is_ah(format)   ((format & HFO_AH)    >> 4)

typedef enum
{
  HF_UNSPEC = 0,
  HF_INET_TCP = HFO_INET | HFO_TCP,
  HF_INET6_TCP = HFO_INET6 | HFO_TCP,
  HF_INET_ICMP = HFO_INET | HFO_ICMP,
  HF_INET6_ICMP = HFO_INET6 | HFO_ICMP,
  HF_INET_TCP_AH = HFO_INET | HFO_TCP | HFO_AH,
  HF_INET6_TCP_AH = HFO_INET6 | HFO_TCP | HFO_AH,
  HF_INET_ICMP_AH = HFO_INET | HFO_ICMP | HFO_AH,
  HF_INET6_ICMP_AH = HFO_INET6 | HFO_ICMP | HFO_AH
} hicn_format_t;

/**
 * Minimum required header length to determine the type and length of a supposed
 * hICN packet.
 * This should be equal to the maximum value over all possible hICN packet
 * formats, and less than the minimum possible IP packet size.
 */
#define HICN_V6_MIN_HDR_LEN 6	/* bytes */
#define HICN_V4_MIN_HDR_LEN 4	/* bytes */

// #define HICN_MIN_HDR_LEN ((HICN_V6_MIN_HDR_LEN > HICN_V4_MIN_HDR_LEN) ? HICN_V6_MIN_HDR_LEN : HICN_V4_MIN_HDR_LEN)
#define HICN_MIN_HDR_LEN HICN_V6_MIN_HDR_LEN

/**
 * @brief Parse packet headers and return hICN format
 * @param [in] format - hICN Format
 * @param [in, out] packet - Buffer containing the hICN header to be initialized
 * @return hICN error code
 */
int hicn_packet_init_header (hicn_format_t format, hicn_header_t * packet);

/**
 * @brief Parse packet headers and return hICN format
 * @param [in] h - hICN header
 * @param [out] format - hICN format
 * @return hICN error code
 */
int hicn_packet_get_format (const hicn_header_t * packet,
			    hicn_format_t * format);

#if 0
/**
 * @brief Update checksums in packet headers
 * @param [in] format - hICN format
 * @param [in,out] packet - packet header
 * @return hICN error code
 */
int hicn_packet_compute_checksum (hicn_format_t format,
				  hicn_header_t * packet);

/**
 * @brief compute the checksum of the packet header, adding init_sum to the final value
 * @param [in] format - hICN format
 * @param [in,out] packet - packet header
 * @param [in] init_sum - value to add to the final checksum
 * @return hICN error code
 */
int hicn_packet_compute_header_checksum (hicn_format_t format,
					 hicn_header_t * packet,
					 u16 init_sum);

/**
 * @brief Verify checksums in packet headers
 * @param [in] format - hICN format
 * @param [in,out] packet - packet header
 * @return hICN error code
 */
int hicn_packet_check_integrity (hicn_format_t format,
				 hicn_header_t * packet);

#endif
// this is not accounted here
/**
 * @brief Return total length of hicn headers (but signature payload)
 * @param [in] format - hICN format
 * @param [out] header_length - Total length of headers
 * @return hICN error code
 */
int hicn_packet_get_header_length_from_format (hicn_format_t format,
					       size_t * header_length);

/**
 * @brief Return total length of hicn headers (before payload)
 * @param [in] format - hICN format
 * @param [in] packet - packet header
 * @param [out] header_length - Total length of headers
 * @return hICN error code
 */
int hicn_packet_get_header_length (hicn_format_t format,
				   const hicn_header_t * packet,
				   size_t * header_length);

/**
 * @brief Return payload length
 * @param [in] format - hICN format
 * @param [in] packet - packet header
 * @param [out] payload_length - payload length
 * @return hICN error code
 */
int hicn_packet_get_payload_length (hicn_format_t format,
				    const hicn_header_t * packet,
				    size_t * payload_length);

/**
 * @brief Sets payload length
 * @param [in] format - hICN format
 * @param [in,out] packet - packet header
 * @param [in] payload_length - payload length
 * @return hICN error code
 */
int hicn_packet_set_payload_length (hicn_format_t format,
				    hicn_header_t * packet,
				    const size_t payload_length);

/**
 * @brief Compare two hICN packets
 * @param [in] packet_1 - First packet
 * @param [in] packet_2 - Second packet
 * @return 0 if both packets are considered equal, any other value otherwise.
 */
int hicn_packet_compare (const hicn_header_t * packet1,
			 const hicn_header_t * packet2);

/**
 * @brief Retrieve the name of an interest/data packet
 * @param [in] format - hICN format
 * @param [in] packet - packet header
 * @param [out] name - name holding the result
 * @param [in] is_interest - Flag to determine whether it is an interest (1) or
 * data packet (0)
 * @return hICN error code
 */
int hicn_packet_get_name (hicn_format_t format, const hicn_header_t * packet,
			  hicn_name_t * name, u8 is_interest);

/**
 * @brief Sets the name of an interest/data packet
 * @param [in] format - hICN format
 * @param [in,out] packet - packet header
 * @param [in] name - name to set into packet
 * @param [in] is_interest - Flag to determine whether it is an interest (1) or
 * data packet (0)
 * @return hICN error code
 */
int hicn_packet_set_name (hicn_format_t format, hicn_header_t * packet,
			  const hicn_name_t * name, u8 is_interest);

/**
 * @brief Sets the payload of a packet
 * @param [in] format - hICN format
 * @param [in,out] packet - packet header
 * @param [in] payload - payload to set
 * @param [in] payload_length - size of the payload to set
 * @return hICN error code
 *
 * NOTE:
 *  - The buffer holding payload is assumed sufficiently large
 *  - This function updates header fields with the new length, but no checksum.
 */
int hicn_packet_set_payload (hicn_format_t format, hicn_header_t * packet,
			     const u8 * payload, u16 payload_length);

/**
 * @brief Retrieves the payload of a packet
 * @param [in] format - hICN format
 * @param [in] packet - packet header
 * @param [out] payload - pointer to buffer for storing the result
 * @param [out] payload_length - size of the retreived payload
 * @param [in] hard_copy - Flag : if true (eg. 1), a copy of the payload is made
 * into the payload buffer, otherwise (0) the pointer is changed to point to the payload offset in the packet.
 * @return hICN error code
 *
 * NOTE:
 *  - The buffer holding payload is assumed sufficiently large
 */
int hicn_packet_get_payload (hicn_format_t format,
			     const hicn_header_t * packet, u8 ** payload,
			     size_t * payload_size, bool hard_copy);

/**
 * @brief Retrieve the locator of an interest / data packet
 * @param [in] format - hICN format
 * @param [in] packet - packet header
 * @param [out] ip_address - retrieved locator
 * @param [in] is_interest - Flag to determine whether it is an interest (1) or
 * data packet (0)
 * @return hICN error code
 */
int hicn_packet_get_locator (hicn_format_t format,
			     const hicn_header_t * packet,
			     ip_address_t * prefix, bool is_interest);

/**
 * @brief Sets the locator of an interest / data packet
 * @param [in] format - hICN format
 * @param [in,out] packet - packet header
 * @param [out] ip_address - retrieved locator
 * @param [in] is_interest - Flag to determine whether it is an interest (1) or
 * data packet (0)
 * @return hICN error code
 */
int hicn_packet_set_locator (hicn_format_t format, hicn_header_t * packet,
			     const ip_address_t * prefix,
			     bool is_interest);

/**
 * @brief Retrieves the signature size
 * @param [in] format - hICN format
 * @param [in] packet - packet header
 * @param [out] bytes - Retrieved signature size
 * @return hICN error code
 */
int hicn_packet_get_signature_size (hicn_format_t format,
				    const hicn_header_t * packet,
				    size_t * bytes);

/**
 * @brief Sets the signature size
 * @param [in] format - hICN format
 * @param [in] packet - packet header
 * @param [in] bytes - Retrieved signature size
 * @return hICN error code
 */
int hicn_packet_set_signature_size (hicn_format_t format,
				    hicn_header_t * packet, size_t bytes);

/**
 * @brief Sets the signature size
 * @param [in] format - hICN format
 * @param [in] packet - packet header
 * @param [in] signature_timestamp - Signature timestamp to set
 * @return hICN error code
 */
int hicn_packet_set_signature_timestamp (hicn_format_t format,
					 hicn_header_t * h,
					 uint64_t signature_timestamp);

/**
 * @brief Sets the signature size
 * @param [in] format - hICN format
 * @param [in] packet - packet header
 * @param [out] signature_timestamp - Retrieved signature timestamp
 * @return hICN error code
 */
int hicn_packet_get_signature_timestamp (hicn_format_t format,
					 const hicn_header_t * h,
					 uint64_t * signature_timestamp);

/**
 * @brief Sets the signature size
 * @param [in] format - hICN format
 * @param [in] packet - packet header
 * @param [in] validation_algorithm - Validation algorithm to set
 * @return hICN error code
 */
int hicn_packet_set_validation_algorithm (hicn_format_t format,
					  hicn_header_t * h,
					  uint8_t validation_algorithm);

/**
 * @brief Sets the signature size
 * @param [in] format - hICN format
 * @param [in] packet - packet header
 * @param [out] validation_algorithm - Retrieved validation algorithm
 * @return hICN error code
 */
int hicn_packet_get_validation_algorithm (hicn_format_t format,
					  const hicn_header_t * h,
					  uint8_t * validation_algorithm);

/**
 * @brief Sets the signature size
 * @param [in] format - hICN format
 * @param [in] packet - packet header
 * @param [in] key_id - Key id to set
 * @return hICN error code
 */
int hicn_packet_set_key_id (hicn_format_t format, hicn_header_t * h,
			    uint8_t * key_id);

/**
 * @brief Sets the signature size
 * @param [in] format - hICN format
 * @param [in] packet - packet header
 * @param [out] key_id - Retrieved key id
 * @return hICN error code
 */
int hicn_packet_get_key_id (hicn_format_t format, hicn_header_t * h,
			    uint8_t ** key_id, uint8_t * key_id_length);

/**
 * @brief Retrieves the packet hop limit
 * @param [in] packet - packet header
 * @param [out] hops - Retrieved hop limit
 * @return hICN error code
 */
int hicn_packet_get_hoplimit (const hicn_header_t * packet, u8 * hops);

/**
 * @brief Sets the packet hop limit
 * @param [in] packet - packet header
 * @param [in] hops - Hop limit to set
 * @return hICN error code
 */
int hicn_packet_set_hoplimit (hicn_header_t * packet, u8 hops);

int hicn_packet_copy_header (hicn_format_t format,
			     const hicn_header_t * packet,
			     hicn_header_t * destination, bool copy_ah);

int hicn_packet_get_lifetime (const hicn_header_t * packet, u32 * lifetime);
int hicn_packet_set_lifetime (hicn_header_t * packet, u32 lifetime);
int hicn_packet_get_reserved_bits (const hicn_header_t * packet,
				   u8 * reserved_bits);
int hicn_packet_set_reserved_bits (hicn_header_t * packet,
				   const u8 reserved_bits);
int hicn_packet_get_payload_type (const hicn_header_t * packet,
				  hicn_payload_type_t * payload_type);
int hicn_packet_set_payload_type (hicn_header_t * packet,
				  const hicn_payload_type_t payload_type);

int hicn_packet_set_syn (hicn_header_t * packet);
int hicn_packet_reset_syn (hicn_header_t * packet);
int hicn_packet_test_syn (const hicn_header_t * packet, bool * flag);
int hicn_packet_set_ack (hicn_header_t * packet);
int hicn_packet_reset_ack (hicn_header_t * packet);
int hicn_packet_test_ack (const hicn_header_t * packet, bool * flag);
int hicn_packet_set_rst (hicn_header_t * packet);
int hicn_packet_reset_rst (hicn_header_t * packet);
int hicn_packet_test_rst (const hicn_header_t * packet, bool * flag);
int hicn_packet_set_fin (hicn_header_t * packet);
int hicn_packet_reset_fin (hicn_header_t * packet);
int hicn_packet_test_fin (const hicn_header_t * packet, bool * flag);
int hicn_packet_set_ece (hicn_header_t * packet);
int hicn_packet_reset_ece (hicn_header_t * packet);
int hicn_packet_test_ece (const hicn_header_t * packet, bool * flag);

int hicn_packet_set_src_port (hicn_header_t * packet, u16 src_port);
int hicn_packet_get_src_port (const hicn_header_t * packet, u16 * src_port);
int hicn_packet_set_dst_port (hicn_header_t * packet, u16 dst_port);
int hicn_packet_get_dst_port (const hicn_header_t * packet, u16 * dst_port);
int hicn_packet_get_signature (hicn_format_t format, hicn_header_t * packet,
			       uint8_t ** sign_buf);

/* Interest */
int hicn_interest_get_name (hicn_format_t format,
			    const hicn_header_t * interest,
			    hicn_name_t * name);
int hicn_interest_set_name (hicn_format_t format, hicn_header_t * interest,
			    const hicn_name_t * name);
int hicn_interest_get_locator (hicn_format_t format,
			       const hicn_header_t * interest,
			       ip_address_t * prefix);
int hicn_interest_set_locator (hicn_format_t format, hicn_header_t * interest,
			       const ip_address_t * prefix);
int hicn_interest_compare (const hicn_header_t * interest_1,
			   const hicn_header_t * interest_2);
int hicn_interest_set_lifetime (hicn_header_t * interest, u32 lifetime);
int hicn_interest_get_lifetime (const hicn_header_t * interest,
				u32 * lifetime);
int hicn_interest_get_header_length (hicn_format_t format,
				     const hicn_header_t * interest,
				     size_t * header_length);
int hicn_interest_get_payload_length (hicn_format_t format,
				      const hicn_header_t * interest,
				      size_t * payload_length);
int hicn_interest_set_payload (hicn_format_t format, hicn_header_t * interest,
			       const u8 * payload, size_t payload_length);
int hicn_interest_get_payload (hicn_format_t format,
			       const hicn_header_t * interest, u8 ** payload,
			       size_t * payload_size, bool hard_copy);
int hicn_interest_reset_for_hash (hicn_format_t format,
				  hicn_header_t * packet);

/* Data */

int hicn_data_get_name (hicn_format_t format, const hicn_header_t * data,
			hicn_name_t * name);
int hicn_data_set_name (hicn_format_t format, hicn_header_t * data,
			const hicn_name_t * name);
int hicn_data_get_locator (hicn_format_t format, const hicn_header_t * data,
			   ip_address_t * prefix);
int hicn_data_set_locator (hicn_format_t format, hicn_header_t * data,
			   const ip_address_t * prefix);
int hicn_data_compare (const hicn_header_t * data_1,
		       const hicn_header_t * data_2);
int hicn_data_get_expiry_time (const hicn_header_t * data, u32 * expiry_time);
int hicn_data_set_expiry_time (hicn_header_t * data, u32 expiry_time);
int hicn_data_get_header_length (hicn_format_t format, hicn_header_t * data,
				 size_t * header_length);
int hicn_data_get_payload_length (hicn_format_t format,
				  const hicn_header_t * data,
				  size_t * payload_length);
int hicn_data_get_path_label (const hicn_header_t * data, u32 * path_label);
int hicn_data_set_path_label (hicn_header_t * data, u32 path_label);
int hicn_data_get_payload (hicn_format_t format, const hicn_header_t * data,
			   u8 ** payload, size_t * payload_size,
			   bool hard_copy);
int hicn_data_set_payload (hicn_format_t format, hicn_header_t * data,
			   const u8 * payload, size_t payload_length);
int hicn_data_get_payload_type (const hicn_header_t * data,
				hicn_payload_type_t * payload_type);
int hicn_data_set_payload_type (hicn_header_t * data,
				hicn_payload_type_t payload_type);
int hicn_data_reset_for_hash (hicn_format_t format, hicn_header_t * packet);

#endif /* HICN_COMPAT_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
