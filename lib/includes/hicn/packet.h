/*
 * Copyright (c) 2017-2022 Cisco and/or its affiliates.
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
 *
 */
#ifndef HICN_PACKET_H
#define HICN_PACKET_H

#include <limits.h>

#include <hicn/base.h>
#include <hicn/common.h>
#include <hicn/name.h>

/* Packet buffer definition */

typedef struct __attribute__ ((packed))
{
  /* Packet format */
  hicn_packet_format_t format;

  /* Packet type */
  hicn_packet_type_t type;

  /*
   * We store an offset to the packet header.
   *
   * NOTE: This is a signed value.
   *
   * In most implementations, the buffer located closeby to the current packet
   * buffer (eg msgbuf in hicn-light, and vlib buffer in VPP), and an int16_t
   * would be sufficient. This is not the case in transport though and we have
   * to use a full integer.
   */
  int64_t header;

  /* Packet len */
  uint16_t len;

#ifdef OPAQUE_IP
  /* Interest or data packet */
  union
  {
    uint16_t ipv4;
    uint16_t ipv6;
  };
#endif /* OPAQUE_IP */
  union
  {
    uint16_t tcp;
    uint16_t udp;
    uint16_t icmp;
  };
  uint16_t newhdr;
  uint16_t ah;
  uint16_t payload;

  uint16_t buffer_size;
  // uint16_t len;

  /* Contiguous copy of the name */
  // hicn_name_t *name;

} hicn_packet_buffer_t;

static_assert (sizeof (hicn_packet_buffer_t) == 28, "");

static inline uint8_t *
_pkbuf_get_ipv4 (const hicn_packet_buffer_t *pkbuf)
{
#ifdef OPAQUE_IP
  uint8_t *header = (uint8_t *) pkbuf + pkbuf->header + pkbuf->ipv4;
#else
  uint8_t *header = (uint8_t *) pkbuf + pkbuf->header;
#endif
  _ASSERT (header);
  return header;
}
#define pkbuf_get_ipv4(pkbuf) ((_ipv4_header_t *) (_pkbuf_get_ipv4 (pkbuf)))

static inline uint8_t *
_pkbuf_get_ipv6 (const hicn_packet_buffer_t *pkbuf)
{
#ifdef OPAQUE_IP
  uint8_t *header = (uint8_t *) pkbuf + pkbuf->header + pkbuf->ipv6;
#else
  uint8_t *header = (uint8_t *) pkbuf + pkbuf->header;
#endif
  assert (header);
  return header;
}
#define pkbuf_get_ipv6(pkbuf) ((_ipv6_header_t *) (_pkbuf_get_ipv6 (pkbuf)))

static inline uint8_t *
_pkbuf_get_tcp (const hicn_packet_buffer_t *pkbuf)
{
  uint8_t *header = (uint8_t *) pkbuf + pkbuf->header + pkbuf->tcp;
  assert (header);
  return header;
}
#define pkbuf_get_tcp(pkbuf) ((_tcp_header_t *) (_pkbuf_get_tcp (pkbuf)))

static inline uint8_t *
_pkbuf_get_udp (const hicn_packet_buffer_t *pkbuf)
{
  uint8_t *header = (uint8_t *) pkbuf + pkbuf->header + pkbuf->udp;
  assert (header);
  return header;
}
#define pkbuf_get_udp(pkbuf) ((_udp_header_t *) (_pkbuf_get_udp (pkbuf)))

static inline uint8_t *
_pkbuf_get_icmp (const hicn_packet_buffer_t *pkbuf)
{
  uint8_t *header = (uint8_t *) pkbuf + pkbuf->header + pkbuf->icmp;
  assert (header);
  return header;
}
#define pkbuf_get_icmp(pkbuf) ((_icmp_header_t *) (_pkbuf_get_icmp (pkbuf)))

static inline uint8_t *
_pkbuf_get_ah (const hicn_packet_buffer_t *pkbuf)
{
  uint8_t *header = (uint8_t *) pkbuf + pkbuf->header + pkbuf->ah;
  assert (header);
  return header;
}
#define pkbuf_get_ah(pkbuf) ((_ah_header_t *) (_pkbuf_get_ah (pkbuf)))

static inline uint8_t *
_pkbuf_get_new (const hicn_packet_buffer_t *pkbuf)
{
  uint8_t *header = (uint8_t *) pkbuf + pkbuf->header + pkbuf->newhdr;
  assert (header);
  return header;
}
#define pkbuf_get_new(pkbuf) ((_new_header_t *) (_pkbuf_get_new (pkbuf)))

static inline uint8_t *
pkbuf_get_header (const hicn_packet_buffer_t *pkbuf)
{
  uint8_t *header = (uint8_t *) pkbuf + pkbuf->header;
  assert (header);
  return header;
}

static inline void
pkbuf_set_header (hicn_packet_buffer_t *pkbuf, uint8_t *header)
{
  ssize_t offset = header - (uint8_t *) pkbuf;
  assert (offset < INT64_MAX);
  assert (offset > INT64_MIN);
  pkbuf->header = (int64_t) offset;
}

/*
 * Packet buffer operations
 *
 * A packet buffer can either be initialized either:
 *
 * 1) from an empty buffer (packet crafting).
 *
 * #define MTU 1500
 * size_t size = MTU;
 * u8 buffer[MTU];
 *
 * hicn_packet_t pkbuf;
 * hicn_packet_set_format(&pkbuf, HICN_PACKET_FORMAT_NEW);
 * hicn_packet_set_buffer(&pkbuf, &buffer, size);
 * hicn_packet_init_header(&pkbuf, 0);
 *
 * An empty (but correct) packet is not available in the buffer, ready to be
 * modified and/or sent.
 *
 * 2) from an existing buffer (packet reception):
 *
 * hicn_packet_t pkbuf;
 * hicn_packet_set_buffer(&pkbuf, &buffer, size);
 * hicn_packet_analyze(&pkbuf);
 *
 * It is then possible to retrieve properties of the packet such as format and
 * type (interest, data, etc.).
 *
 * hicn_packet_get_format(&pkbuf);
 * hicn_packet_get_type(&pkbuf);
 *
 * */

hicn_packet_format_t
hicn_packet_get_format (const hicn_packet_buffer_t *pkbuf);

void hicn_packet_set_format (hicn_packet_buffer_t *pkbuf,
			     hicn_packet_format_t format);

hicn_packet_type_t hicn_packet_get_type (const hicn_packet_buffer_t *pkbuf);
void hicn_packet_set_type (hicn_packet_buffer_t *pkbuf,
			   hicn_packet_type_t type);

bool hicn_packet_is_interest (const hicn_packet_buffer_t *pkbuf);

bool hicn_packet_is_data (const hicn_packet_buffer_t *pkbuf);

bool hicn_packet_is_undefined (const hicn_packet_buffer_t *pkbuf);

/**
 * @brief Initialize the buffer from packet buffer metadata (builds a valid
 * packet).
 * @param [in] pkbuf - hICN packet buffer
 * @return hICN error code
 *
 * Packet type, format, and a buffer are required.
 */
int hicn_packet_init_header (hicn_packet_buffer_t *pkbuf,
			     size_t additional_header_size);

/**
 * @brief Reset information stored in the packet header.
 * @param [in] pkbuf - hICN packet buffer
 * @return hICN error code
 */
int hicn_packet_reset (hicn_packet_buffer_t *pkbuf);

/**
 * @brief Analyze buffer to populate metadata in packet buffer.
 * @param [in] pkbuf - hICN packet buffer
 * @return hICN error code
 */
int hicn_packet_analyze (hicn_packet_buffer_t *pkbuf);

/**
 * @brief Initialize hicn packet storage space with a buffer
 * @param [in] pkbuf - hICN packet buffer
 * @param [in] buffer - Packet storage buffer
 * @param [in] analyze - Flag indicating whether to analyze the buffer
 * content to populate packet format, header's offsets, etc.
 * @return hICN error code
 */
int hicn_packet_set_buffer (hicn_packet_buffer_t *pkbuf, u8 *buffer,
			    uint16_t buffer_size, uint16_t len);

/**
 * @brief Retrieve the storage buffer.
 * @param [in] pkbuf - hICN packet buffer
 * @param [out] buffer - Packet buffer
 * @param [out] buffer_size - Packet buffer size
 * @return Pointer to storage buffer (this only returns the pointer; no copy is
 * made)
 */
int hicn_packet_get_buffer (const hicn_packet_buffer_t *pkbuf, u8 **buffer,
			    uint16_t *buffer_size, uint16_t *len);

/**
 * @brief Retrieve the packet length
 * @param [in] pkbuf - hICN packet buffer
 * @return Length of the stored packet
 */
size_t hicn_packet_get_len (const hicn_packet_buffer_t *pkbuf);

/**
 * @brief Set the packet length
 * @param [in] pkbuf - hICN packet buffer
 * @param [in] len - hICN packet length
 * @return None
 */
int hicn_packet_set_len (hicn_packet_buffer_t *pkbuf, size_t len);

/**
 * @brief Return total length of hicn headers (before payload)
 * @param [in] pkbuf - hICN packet buffer
 * @param [out] len - Total headers length
 * @return Headers' len
 */
int hicn_packet_get_header_len (const hicn_packet_buffer_t *pkbuf,
				size_t *len);

/**
 * @brief Return the length of hICN payload in the packet.
 * @param [in] pkbuf - hICN packet buffer
 * @param [out] len - hICN payload length
 * @return Payload len
 */
int hicn_packet_get_payload_len (const hicn_packet_buffer_t *pkbuf,
				 size_t *len);

/**
 * @brief Sets the payload of a packet
 * @param [in] pkbuf - hICN packet buffer
 * @param [in,out] packet - packet header
 * @param [in] payload - payload to set
 * @param [in] payload_length - size of the payload to set
 * @return hICN error code
 *
 * NOTE:
 *  - The buffer holding payload is assumed sufficiently large
 *  - This function updates header fields with the new length, but no checksum.
 */
int hicn_packet_set_payload (const hicn_packet_buffer_t *pkbuf,
			     const u8 *payload, u16 payload_length);

/**
 * @brief Retrieves the payload of a packet
 * @param [in] pkbuf - hICN packet buffer
 * @param [in] packet - packet header
 * @param [out] payload - pointer to buffer for storing the result
 * @param [out] payload_length - size of the retreived payload
 * @param [in] hard_copy - Flag : if true (eg. 1), a copy of the payload is
 * made into the payload buffer, otherwise (0) the pointer is changed to point
 * to the payload offset in the packet.
 * @return hICN error code
 *
 * NOTE:
 *  - The buffer holding payload is assumed sufficiently large
 */
int hicn_packet_get_payload (const hicn_packet_buffer_t *pkbuf, u8 **payload,
			     size_t *payload_size, bool hard_copy);

/* Header fields manipulation */

/**
 * @brief Return total length of hicn headers (but signature payload)
 * @param [in] pkbuf - hICN packet buffer
 * @param [out] header_length - Total length of headers
 * @return hICN error code
 */
int hicn_packet_get_header_length_from_format (hicn_packet_format_t format,
					       size_t *header_length);

/**
 * @brief Sets payload length
 * @param [in] pkbuf - hICN packet buffer
 * @param [in,out] packet - packet header
 * @param [in] payload_length - payload length
 * @return hICN error code
 */
int hicn_packet_set_payload_length (const hicn_packet_buffer_t *pkbuf,
				    const size_t payload_length);

/**
 * @brief Compare two hICN packets
 * @param [in] packet_1 - First packet
 * @param [in] packet_2 - Second packet
 * @return 0 if both packets are considered equal, any other value otherwise.
 */
int hicn_packet_compare (const hicn_packet_buffer_t *pkbuf11,
			 const hicn_packet_buffer_t *pkbuf22);

/**
 * @brief Retrieve the name of an interest/data packet
 * @param [in] pkbuf - hICN packet buffer
 * @param [in] packet - packet header
 * @param [out] name - name holding the result
 * @return hICN error code
 */
int hicn_packet_get_name (const hicn_packet_buffer_t *pkbuf,
			  hicn_name_t *name);

/**
 * @brief Sets the name of an interest/data packet
 * @param [in] pkbuf - hICN packet buffer
 * @param [in,out] packet - packet header
 * @param [in] name - name to set into packet
 * @return hICN error code
 */
int hicn_packet_set_name (const hicn_packet_buffer_t *pkbuf,
			  const hicn_name_t *name);

/**
 * @brief Retrieve the locator of an interest / data packet
 * @param [in] pkbuf - hICN packet buffer
 * @param [in] packet - packet header
 * @param [out] ip_address - retrieved locator
 * @return hICN error code
 */
int hicn_packet_get_locator (const hicn_packet_buffer_t *pkbuf,
			     hicn_ip_address_t *prefix);

/**
 * @brief Sets the locator of an interest / data packet
 * @param [in] pkbuf - hICN packet buffer
 * @param [in,out] packet - packet header
 * @param [out] ip_address - retrieved locator
 * @return hICN error code
 */
int hicn_packet_set_locator (const hicn_packet_buffer_t *pkbuf,
			     const hicn_ip_address_t *prefix);

int hicn_packet_save_header (const hicn_packet_buffer_t *pkbuf, u8 *header,
			     size_t *header_len, bool copy_ah);

int hicn_packet_load_header (const hicn_packet_buffer_t *pkbuf,
			     const u8 *header, size_t header_len);

int hicn_packet_get_lifetime (const hicn_packet_buffer_t *pkbuf,
			      u32 *lifetime);
int hicn_packet_set_lifetime (const hicn_packet_buffer_t *pkbuf, u32 lifetime);

/* Interest */
int hicn_interest_get_name (const hicn_packet_buffer_t *pkbuf,
			    hicn_name_t *name);
int hicn_interest_set_name (const hicn_packet_buffer_t *pkbuf,
			    const hicn_name_t *name);
int hicn_interest_get_locator (const hicn_packet_buffer_t *pkbuf,
			       hicn_ip_address_t *prefix);
int hicn_interest_set_locator (const hicn_packet_buffer_t *pkbuf,
			       const hicn_ip_address_t *prefix);
int hicn_interest_compare (const hicn_packet_buffer_t *pkbuf11,
			   const hicn_packet_buffer_t *pkbuf2);
int hicn_interest_set_lifetime (const hicn_packet_buffer_t *pkbuf,
				u32 lifetime);
int hicn_interest_get_lifetime (const hicn_packet_buffer_t *pkbuf,
				u32 *lifetime);
int hicn_interest_get_header_length (const hicn_packet_buffer_t *pkbuf,
				     size_t *header_length);
int hicn_interest_get_payload_length (const hicn_packet_buffer_t *pkbuf,
				      size_t *payload_length);
int hicn_interest_set_payload (const hicn_packet_buffer_t *pkbuf,
			       const u8 *payload, size_t payload_length);
int hicn_interest_get_payload (const hicn_packet_buffer_t *pkbuf, u8 **payload,
			       size_t *payload_size, bool hard_copy);
int hicn_interest_reset_for_hash (hicn_packet_buffer_t *pkbuf);

/* Data */

int hicn_data_get_name (const hicn_packet_buffer_t *pkbuf, hicn_name_t *name);
int hicn_data_set_name (const hicn_packet_buffer_t *pkbuf,
			const hicn_name_t *name);
int hicn_data_get_locator (const hicn_packet_buffer_t *pkbuf,
			   hicn_ip_address_t *prefix);
int hicn_data_set_locator (const hicn_packet_buffer_t *pkbuf,
			   const hicn_ip_address_t *prefix);
int hicn_data_compare (const hicn_packet_buffer_t *pkbuf11,
		       const hicn_packet_buffer_t *pkbuf22);
int hicn_data_get_expiry_time (const hicn_packet_buffer_t *pkbuf,
			       u32 *expiry_time);
int hicn_data_set_expiry_time (const hicn_packet_buffer_t *pkbuf,
			       u32 expiry_time);
int hicn_data_get_header_length (const hicn_packet_buffer_t *pkbuf,
				 size_t *header_length);
int hicn_data_get_payload_length (const hicn_packet_buffer_t *pkbuf,
				  size_t *payload_length);

/* Path label */

/**
 * @brief Returns the path label from a data packet
 * @param [in] pkbuf - packet buffer
 * @param [in] hdr - packet header
 * @param [in] path_label - pointer in which to store the path label value
 * @return hICN error code
 */
int hicn_data_get_path_label (const hicn_packet_buffer_t *pkbufdr,
			      hicn_path_label_t *path_label);

/**
 * @brief Returns the path label from a packet
 * @param [in] pkbuf - packet buffer
 * @param [in] hdr - packet header
 * @param [in] path_label - pointer in which to store the path label value
 * @return hICN error code
 */
int hicn_get_path_label (const hicn_packet_buffer_t *pkbufdr,
			 hicn_path_label_t *path_label);

int hicn_data_set_path_label (const hicn_packet_buffer_t *pkbuf,
			      hicn_path_label_t path_label);

/* Data specific flags */

int hicn_packet_get_payload_type (const hicn_packet_buffer_t *pkbuf,

				  hicn_payload_type_t *payload_type);
int hicn_packet_set_payload_type (const hicn_packet_buffer_t *pkbuf,

				  const hicn_payload_type_t payload_type);

int hicn_data_get_payload (const hicn_packet_buffer_t *pkbuf, u8 **payload,
			   size_t *payload_size, bool hard_copy);
int hicn_data_set_payload (const hicn_packet_buffer_t *pkbuf,
			   const u8 *payload, size_t payload_length);
int hicn_data_get_payload_type (hicn_payload_type_t *payload_type);
int hicn_data_set_payload_type (hicn_payload_type_t payload_type);
int hicn_data_reset_for_hash (hicn_packet_buffer_t *pkbuf);
int hicn_data_is_last (const hicn_packet_buffer_t *pkbuf, int *is_last);
int hicn_data_set_last (const hicn_packet_buffer_t *pkbuf);

/* Security */

/**
 * @brief Retrieves the signature size
 * @param [in] pkbuf - hICN packet buffer
 * @param [in] packet - packet header
 * @param [out] bytes - Retrieved signature size
 * @return hICN error code
 */
int hicn_packet_get_signature_size (const hicn_packet_buffer_t *pkbuf,
				    size_t *bytes);

/**
 * @brief Sets the signature size
 * @param [in] pkbuf - hICN packet buffer
 * @param [in] packet - packet header
 * @param [in] bytes - Retrieved signature size
 * @return hICN error code
 */
int hicn_packet_set_signature_size (const hicn_packet_buffer_t *pkbuf,
				    size_t bytes);

/**
 * @brief Sets the signature size
 * @param [in] pkbuf - hICN packet buffer
 * @param [in] packet - packet header
 * @param [in] signature_timestamp - Signature timestamp to set
 * @return hICN error code
 */
int hicn_packet_set_signature_timestamp (const hicn_packet_buffer_t *pkbuf,
					 uint64_t signature_timestamp);

/**
 * @brief Sets the signature size
 * @param [in] pkbuf - hICN packet buffer
 * @param [in] packet - packet header
 * @param [out] signature_timestamp - Retrieved signature timestamp
 * @return hICN error code
 */
int hicn_packet_get_signature_timestamp (const hicn_packet_buffer_t *pkbuf,
					 uint64_t *signature_timestamp);

/**
 * @brief Sets the signature size
 * @param [in] pkbuf - hICN packet buffer
 * @param [in] packet - packet header
 * @param [in] validation_algorithm - Validation algorithm to set
 * @return hICN error code
 */
int hicn_packet_set_validation_algorithm (const hicn_packet_buffer_t *pkbuf,
					  uint8_t validation_algorithm);

/**
 * @brief Sets the signature size
 * @param [in] pkbuf - hICN packet buffer
 * @param [in] packet - packet header
 * @param [out] validation_algorithm - Retrieved validation algorithm
 * @return hICN error code
 */
int hicn_packet_get_validation_algorithm (const hicn_packet_buffer_t *pkbuf,
					  uint8_t *validation_algorithm);

/**
 * @brief Sets the signature size
 * @param [in] pkbuf - hICN packet buffer
 * @param [in] packet - packet header
 * @param [in] key_id - Key id to set
 * @param [in] key_len - Key length
 * @return hICN error code
 */
int hicn_packet_set_key_id (const hicn_packet_buffer_t *pkbuf, uint8_t *key_id,
			    size_t key_len);

/**
 * @brief Sets the signature size
 * @param [in] pkbuf - hICN packet buffer
 * @param [in] packet - packet header
 * @param [out] key_id - Retrieved key id
 * @return hICN error code
 */
int hicn_packet_get_key_id (const hicn_packet_buffer_t *pkbuf,
			    uint8_t **key_id, uint8_t *key_id_length);

int hicn_packet_get_signature (const hicn_packet_buffer_t *pkbuf,
			       uint8_t **sign_buf);

int hicn_packet_get_signature_padding (const hicn_packet_buffer_t *pkbuf,
				       size_t *bytes);
int hicn_packet_set_signature_padding (const hicn_packet_buffer_t *pkbuf,
				       size_t bytes);

/* Checksums */

/**
 * @brief Update checksums in packet headers
 * @param [in] pkbuf - hICN packet buffer
 * @param [in,out] packet - packet header
 * @return hICN error code
 */
int hicn_packet_compute_checksum (const hicn_packet_buffer_t *pkbuf);

/**
 * @brief compute the checksum of the packet header, adding init_sum to the
 * final value
 * @param [in] pkbuf - hICN packet buffer
 * @param [in,out] packet - packet header
 * @param [in] init_sum - value to add to the final checksum
 * @return hICN error code
 */
int hicn_packet_compute_header_checksum (const hicn_packet_buffer_t *pkbuf,
					 u16 init_sum);

/**
 * @brief Verify checksums in packet headers
 * @param [in] pkbuf - hICN packet buffer
 * @param [in,out] packet - packet header
 * @return hICN error code
 */
int hicn_packet_check_integrity_no_payload (const hicn_packet_buffer_t *pkbuf,
					    u16 init_sum);

/**
 * @brief Returns the packet TTL
 * @param [in] pkbuf - hICN packet buffer
 * @param [out] hops - Pointer to the variable receiving the TTL value
 * @return hICN error code
 */
int hicn_packet_get_ttl (const hicn_packet_buffer_t *pkbuf, u8 *hops);

/**
 * @brief Returns the packet source port
 * @param [in] pkbuf - hICN packet buffer
 * @param [in, out] pos - Current position in the sequence of headers while
 * @param [out] hops - The TTL value to set
 * @return hICN error code
 */
int hicn_packet_set_ttl (const hicn_packet_buffer_t *pkbuf, u8 hops);

/**
 * @brief Returns the packet source port
 * @param [in] pkbuf - hICN packet buffer
 * @param [out] port - Pointer to the variable that will receive the port
 * number
 * @return hICN error code
 */
int hicn_packet_get_src_port (const hicn_packet_buffer_t *pkbuf, u16 *port);

/**
 * @brief Sets the packet source port
 * @param [in] pkbuf - hICN packet buffer
 * @param [out] port - The port number to set
 * @return hICN error code
 */
int hicn_packet_set_src_port (const hicn_packet_buffer_t *pkbuf, u16 port);

/**
 * @brief Returns the packet source port
 * @param [in] pkbuf - hICN packet buffer
 * @param [out] port - Pointer to the variable that will receive the port
 * number
 * @return hICN error code
 */
int hicn_packet_get_dst_port (const hicn_packet_buffer_t *pkbuf, u16 *port);

/**
 * @brief Sets the packet source port
 * @param [in] pkbuf - hICN packet buffer
 * @param [out] port - The port number to set
 * @return hICN error code
 */
int hicn_packet_set_dst_port (const hicn_packet_buffer_t *pkbuf, u16 port);

int hicn_interest_rewrite (const hicn_packet_buffer_t *pkbuf,
			   const hicn_ip_address_t *addr_new,
			   hicn_ip_address_t *addr_old);

int hicn_data_rewrite (const hicn_packet_buffer_t *pkbuf,
		       const hicn_ip_address_t *addr_new,
		       hicn_ip_address_t *addr_old,
		       const hicn_faceid_t face_id, u8 reset_pl);

#endif /* HICN_PACKET_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
