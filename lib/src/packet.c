/*
 * Copyright (c) 2017-2021 Cisco and/or its affiliates.
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
 * @file packet.c
 * @brief Implementation of the compatibility layer.
 */
#ifndef _WIN32
#include <netinet/in.h>
#endif
#include <string.h> // memset
#include <stddef.h> // offsetof

#include <hicn/common.h>
#include <hicn/packet.h>
#include <hicn/error.h>
#include <hicn/name.h>
#include <hicn/util/log.h>
#include "ops.h"

#define member_size(type, member) sizeof (((type *) 0)->member)
#define ARRAY_SIZE(a)		  (sizeof (a) / sizeof (*(a)))

#define HICN_NAME_COMPONENT_SIZE 2

hicn_packet_format_t
hicn_packet_get_format (const hicn_packet_buffer_t *pkbuf)
{
  return pkbuf->format;
}

void
hicn_packet_set_format (hicn_packet_buffer_t *pkbuf,
			hicn_packet_format_t format)
{
  pkbuf->format = format;
}

hicn_packet_type_t
hicn_packet_get_type (const hicn_packet_buffer_t *pkbuf)
{
  return pkbuf->type;
}

void
hicn_packet_set_type (hicn_packet_buffer_t *pkbuf, hicn_packet_type_t type)
{
  pkbuf->type = type;
}

bool
hicn_packet_is_interest (const hicn_packet_buffer_t *pkbuf)
{
  return pkbuf->type == HICN_PACKET_TYPE_INTEREST;
}

bool
hicn_packet_is_data (const hicn_packet_buffer_t *pkbuf)
{
  return pkbuf->type == HICN_PACKET_TYPE_DATA;
}

bool
hicn_packet_is_undefined (const hicn_packet_buffer_t *pkbuf)
{
  return pkbuf->type == HICN_PACKET_TYPE_UNDEFINED;
}

int
hicn_packet_init_header (hicn_packet_buffer_t *pkbuf,
			 size_t additional_header_size)
{
  if (hicn_packet_is_undefined (pkbuf))
    return HICN_LIB_ERROR_UNEXPECTED;
  if (hicn_packet_get_format (pkbuf).as_u32 == HICN_PACKET_FORMAT_NONE.as_u32)
    return HICN_LIB_ERROR_UNEXPECTED;
  if (!pkbuf_get_header (pkbuf))
    return HICN_LIB_ERROR_UNEXPECTED;
  pkbuf->len = 0;
  pkbuf->payload = 0;

  int rc = CALL (init_packet_header, pkbuf);

  /*
   * Additional header size is there for the signature, and assumes the AH
   * header is always located at the end...
   */
  pkbuf->len += additional_header_size;
  pkbuf->payload += additional_header_size;

  return rc;
}

int
hicn_packet_reset (hicn_packet_buffer_t *pkbuf)
{
  memset (pkbuf, 0, sizeof (hicn_packet_buffer_t));
  hicn_packet_set_format (pkbuf, HICN_PACKET_FORMAT_NONE);
  hicn_packet_set_type (pkbuf, HICN_PACKET_TYPE_UNDEFINED);
  hicn_packet_set_len (pkbuf, 0);

  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_analyze (hicn_packet_buffer_t *pkbuf)
{
  u8 *header = pkbuf_get_header (pkbuf);
  u8 protocol;
  u16 offset = 0;
  bool has_signature;
  size_t signature_size;
  int rc;

  hicn_packet_format_t *format = &pkbuf->format;

  /* Bootstrap: assume IP packet, and get version from header */
  switch (HICN_IP_VERSION (pkbuf_get_header (pkbuf)))
    {
    case 4:
      protocol = IPPROTO_IP;
      break;
    case 6:
      protocol = IPPROTO_IPV6;
      break;
    default:
      goto ERR;
    }

  format->as_u32 = 0;
  for (unsigned i = 0; i < HICN_FORMAT_LEN; i++)
    {
      format->as_u8[i] = protocol;

      /* Next protocol + increment offset */
      switch (protocol)
	{

	/*
	 * All packets either start with IPv4 or IPv6, so we take the
	 * opportunity to update packet length there
	 */
	case IPPROTO_IP:
	  {
	    if (i > 0)
	      goto ERR;
#ifdef OPAQUE_IP
	    pkbuf->ipv4 = offset;
#else
	    assert (offset == 0);
#endif /* OPAQUE_IP */
	    _ipv4_header_t *ipv4 = (_ipv4_header_t *) (header + offset);
	    protocol = ipv4->protocol;
	    offset += IPV4_HDRLEN;

	    // hicn_packet_set_len (pkbuf, htons (ipv4->len));
	    if (hicn_packet_get_len (pkbuf) != htons (ipv4->len))
	      {
		ERROR ("Invalid packet size in IPv4 header %d != %d",
		       htons (ipv4->len), hicn_packet_get_len (pkbuf));
		goto ERR;
	      }
	    break;
	  }
	case IPPROTO_IPV6:
	  {
	    if (i > 0)
	      goto ERR;
#ifdef OPAQUE_IP
	    pkbuf->ipv6 = offset;
#else
	    assert (offset == 0);
#endif /* OPAQUE_IP */
	    _ipv6_header_t *ipv6 = (_ipv6_header_t *) (header + offset);
	    protocol = ipv6->nxt;
	    offset += IPV6_HDRLEN;
	    // hicn_packet_set_len (pkbuf, IPV6_HDRLEN + htons (ipv6->len));
	    if (hicn_packet_get_len (pkbuf) != IPV6_HDRLEN + htons (ipv6->len))
	      {
		ERROR ("Invalid packet size in IPv6 header %d != %d",
		       IPV6_HDRLEN + htons (ipv6->len),
		       hicn_packet_get_len (pkbuf));
		goto ERR;
	      }
	    break;
	  }
	case IPPROTO_TCP:
	  pkbuf->tcp = offset;
	  /* After TCP, we might eventually have a AH header */
	  rc = CALL_CHILD (has_signature, pkbuf, i - 1, &has_signature);
	  if (rc < 0)
	    goto ERR;
	  protocol = has_signature ? IPPROTO_AH : IPPROTO_NONE;
	  offset += TCP_HDRLEN;
	  break;
	case IPPROTO_UDP:
	  pkbuf->udp = offset;
	  protocol = IPPROTO_ENCAP;
	  offset += UDP_HDRLEN;
	  break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
	  pkbuf->icmp = offset;
	  /* After ICMP, we might eventually have a AH header */
	  // CALL_CHILD (has_signature, pkbuf, i - 1, &has_signature);
	  protocol = /* has_signature ? IPPROTO_AH : */ IPPROTO_NONE;
	  offset += ICMP_HDRLEN;
	  break;

	case IPPROTO_ENCAP:
	  pkbuf->newhdr = offset;
	  /* After ENCAP, we might eventually have a AH header */
	  rc = CALL_CHILD (has_signature, pkbuf, i - 1, &has_signature);
	  if (rc < 0)
	    goto ERR;
	  protocol = has_signature ? IPPROTO_AH : IPPROTO_NONE;
	  offset += NEW_HDRLEN;
	  break;

	case IPPROTO_AH:
	  pkbuf->ah = offset;
	  protocol = IPPROTO_NONE;
	  offset += AH_HDRLEN;

	  rc = CALL_CHILD (get_signature_size, pkbuf, i - 1, &signature_size);
	  if (rc < 0)
	    goto ERR;
	  offset += signature_size;
	  break;

	case IPPROTO_NONE:
	  /* NONE until we terminate the list of protocols */
	  break;

	default:
	  goto ERR;
	}
    }
  pkbuf->payload = offset;

  rc = CALL (get_type, pkbuf, &pkbuf->type);
  if (rc < 0)
    goto ERR;

  return HICN_LIB_ERROR_NONE;

ERR:
  *format = HICN_PACKET_FORMAT_NONE;
  pkbuf->type = HICN_PACKET_TYPE_UNDEFINED;
  return HICN_LIB_ERROR_UNEXPECTED;
}

int
hicn_packet_set_buffer (hicn_packet_buffer_t *pkbuf, u8 *buffer,
			uint16_t buffer_size, uint16_t len)
{
  pkbuf_set_header (pkbuf, buffer);
  pkbuf->buffer_size = buffer_size;
  pkbuf->len = len;

  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_get_buffer (const hicn_packet_buffer_t *pkbuf, u8 **buffer,
			uint16_t *buffer_size, uint16_t *len)
{
  *buffer = pkbuf_get_header (pkbuf);
  *buffer_size = pkbuf->buffer_size;
  *len = pkbuf->len;
  return HICN_LIB_ERROR_NONE;
}

size_t
hicn_packet_get_len (const hicn_packet_buffer_t *pkbuf)
{
  return pkbuf->len;
}

int
hicn_packet_set_len (hicn_packet_buffer_t *pkbuf, size_t len)
{
  pkbuf->len = len;
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_get_header_len (const hicn_packet_buffer_t *pkbuf, size_t *len)
{
  *len = pkbuf->payload;
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_get_payload_len (const hicn_packet_buffer_t *pkbuf, size_t *len)
{
  *len = hicn_packet_get_len (pkbuf) - pkbuf->payload;
  return HICN_LIB_ERROR_NONE;
}

// XXX this fails with chained membufs in libtransport
int
hicn_packet_set_payload (const hicn_packet_buffer_t *pkbuf, const u8 *payload,
			 u16 payload_len)
{
  memcpy (pkbuf_get_header (pkbuf) + pkbuf->payload, payload, payload_len);

  return CALL (set_payload_len, pkbuf, payload_len);
}

int
hicn_packet_get_payload (const hicn_packet_buffer_t *pkbuf, u8 **payload,
			 size_t *payload_size, bool hard_copy)
{
  size_t payload_len = hicn_packet_get_len (pkbuf) - pkbuf->payload;

  if (hard_copy)
    {
      memcpy (payload, pkbuf_get_header (pkbuf) + pkbuf->payload, payload_len);
    }
  else
    {
      *payload = pkbuf_get_header (pkbuf) + pkbuf->payload;
    }

  return HICN_LIB_ERROR_NONE;
}

/* Header fields manipulation */

int
hicn_packet_get_header_length_from_format (hicn_packet_format_t format,
					   size_t *header_length)
{
  *header_length = 0;
  for (unsigned i = 0; i < HICN_FORMAT_LEN; i++)
    {
      *header_length += hicn_ops_vft[format.as_u8[i]]->header_len;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_compute_checksum (const hicn_packet_buffer_t *pkbuf)
{
  return CALL (update_checksums, pkbuf, 0, ~0);
}

int
hicn_packet_compute_header_checksum (const hicn_packet_buffer_t *pkbuf,
				     u16 init_sum)
{
  /* payload_len == 0: ignore payload */
  return CALL (update_checksums, pkbuf, init_sum, 0);
}

int
hicn_packet_check_integrity_no_payload (const hicn_packet_buffer_t *pkbuf,
					u16 init_sum)
{
  return CALL (verify_checksums, pkbuf, init_sum, 0);
}

int
hicn_packet_set_payload_length (const hicn_packet_buffer_t *pkbuf,
				const size_t payload_len)
{
  return CALL (set_payload_len, pkbuf, payload_len);
}

int
hicn_packet_compare (const hicn_packet_buffer_t *pkbuf1,
		     const hicn_packet_buffer_t *pkbuf2)
{

  hicn_packet_format_t format1 = hicn_packet_get_format (pkbuf1);
  hicn_packet_format_t format2 = hicn_packet_get_format (pkbuf2);

  if (format1.as_u32 != format2.as_u32)
    return HICN_LIB_ERROR_UNEXPECTED;

  size_t len1 = hicn_packet_get_len (pkbuf1);
  size_t len2 = hicn_packet_get_len (pkbuf2);

  if (len1 != len2)
    return HICN_LIB_ERROR_UNEXPECTED;

  return memcmp (pkbuf_get_header (pkbuf1), pkbuf_get_header (pkbuf2), len1);
}

int
hicn_packet_get_name (const hicn_packet_buffer_t *pkbuf, hicn_name_t *name)
{
  switch (pkbuf->type)
    {
    case HICN_PACKET_TYPE_INTEREST:
      return hicn_interest_get_name (pkbuf, name);
    case HICN_PACKET_TYPE_DATA:
      return hicn_data_get_name (pkbuf, name);
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
}

int
hicn_packet_set_name (const hicn_packet_buffer_t *pkbuf,
		      const hicn_name_t *name)
{
  switch (pkbuf->type)
    {
    case HICN_PACKET_TYPE_INTEREST:
      return hicn_interest_set_name (pkbuf, name);
    case HICN_PACKET_TYPE_DATA:
      return hicn_data_set_name (pkbuf, name);
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
}

int
hicn_packet_get_locator (const hicn_packet_buffer_t *pkbuf,
			 hicn_ip_address_t *address)
{
  switch (pkbuf->type)
    {
    case HICN_PACKET_TYPE_INTEREST:
      return hicn_interest_get_locator (pkbuf, address);
    case HICN_PACKET_TYPE_DATA:
      return hicn_data_get_locator (pkbuf, address);
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
}

int
hicn_packet_set_locator (const hicn_packet_buffer_t *pkbuf,
			 const hicn_ip_address_t *address)
{
  switch (pkbuf->type)
    {
    case HICN_PACKET_TYPE_INTEREST:
      return hicn_interest_set_locator (pkbuf, address);
    case HICN_PACKET_TYPE_DATA:
      return hicn_data_set_locator (pkbuf, address);
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
}

int
hicn_packet_get_signature_size (const hicn_packet_buffer_t *pkbuf,
				size_t *bytes)
{
  return CALL (get_signature_size, pkbuf, bytes);
}

int
hicn_packet_set_signature_size (const hicn_packet_buffer_t *pkbuf,
				size_t bytes)
{
  return CALL (set_signature_size, pkbuf, bytes);
}

int
hicn_packet_get_signature_padding (const hicn_packet_buffer_t *pkbuf,
				   size_t *bytes)
{
  return CALL (get_signature_padding, pkbuf, bytes);
}

int
hicn_packet_set_signature_padding (const hicn_packet_buffer_t *pkbuf,
				   size_t bytes)
{
  return CALL (set_signature_padding, pkbuf, bytes);
}

int
hicn_packet_set_signature_timestamp (const hicn_packet_buffer_t *pkbuf,
				     uint64_t signature_timestamp)
{
  return CALL (set_signature_timestamp, pkbuf, signature_timestamp);
}

int
hicn_packet_get_signature_timestamp (const hicn_packet_buffer_t *pkbuf,
				     uint64_t *signature_timestamp)
{
  return CALL (get_signature_timestamp, pkbuf, signature_timestamp);
}

int
hicn_packet_set_validation_algorithm (const hicn_packet_buffer_t *pkbuf,
				      uint8_t validation_algorithm)
{
  return CALL (set_validation_algorithm, pkbuf, validation_algorithm);
}

int
hicn_packet_get_validation_algorithm (const hicn_packet_buffer_t *pkbuf,
				      uint8_t *validation_algorithm)
{
  return CALL (get_validation_algorithm, pkbuf, validation_algorithm);
}

int
hicn_packet_set_key_id (const hicn_packet_buffer_t *pkbuf, uint8_t *key_id,
			size_t key_len)
{
  return CALL (set_key_id, pkbuf, key_id, key_len);
}

int
hicn_packet_get_key_id (const hicn_packet_buffer_t *pkbuf, uint8_t **key_id,
			uint8_t *key_id_len)
{
  return CALL (get_key_id, pkbuf, key_id, key_id_len);
}

int
hicn_packet_get_lifetime (const hicn_packet_buffer_t *pkbuf,
			  hicn_lifetime_t *lifetime)
{
  return CALL (get_lifetime, pkbuf, lifetime);
}

int
hicn_packet_set_lifetime (const hicn_packet_buffer_t *pkbuf,
			  hicn_lifetime_t lifetime)
{
  return CALL (set_lifetime, pkbuf, lifetime);
}

int
hicn_packet_get_payload_type (const hicn_packet_buffer_t *pkbuf,
			      hicn_payload_type_t *payload_type)
{
  return CALL (get_payload_type, pkbuf, payload_type);
}

int
hicn_packet_set_payload_type (const hicn_packet_buffer_t *pkbuf,
			      hicn_payload_type_t payload_type)
{
  return CALL (set_payload_type, pkbuf, payload_type);
}

int
hicn_packet_save_header (const hicn_packet_buffer_t *pkbuf, u8 *header,
			 size_t *header_len, bool copy_ah)
{
  hicn_packet_format_t format = hicn_packet_get_format (pkbuf);
  if (copy_ah || !_is_ah (format))
    {
      int rc = hicn_packet_get_header_len (pkbuf, header_len);
      if (HICN_LIB_IS_ERROR (rc))
	return rc;
    }
  else
    {
      /* Copy up until the ah header (which we assume is last) */
      *header_len = pkbuf->ah;
    }

  memcpy (header, pkbuf_get_header (pkbuf), *header_len);

  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_load_header (const hicn_packet_buffer_t *pkbuf, const u8 *header,
			 size_t header_len)
{
  memcpy (pkbuf_get_header (pkbuf), header, header_len);

  return HICN_LIB_ERROR_NONE;
}

/* Interest */

int
hicn_interest_get_name (const hicn_packet_buffer_t *pkbuf, hicn_name_t *name)
{
  return CALL (get_interest_name, pkbuf, name);
}

int
hicn_interest_set_name (const hicn_packet_buffer_t *pkbuf,
			const hicn_name_t *name)
{
  return CALL (set_interest_name, pkbuf, name);
}

int
hicn_interest_get_locator (const hicn_packet_buffer_t *pkbuf,
			   hicn_ip_address_t *address)
{
  return CALL (get_interest_locator, pkbuf, address);
}

int
hicn_interest_set_locator (const hicn_packet_buffer_t *pkbuf,
			   const hicn_ip_address_t *address)
{
  return CALL (set_interest_locator, pkbuf, address);
}

int
hicn_interest_compare (const hicn_packet_buffer_t *pkbuf1,
		       const hicn_packet_buffer_t *pkbuf2)
{
  return hicn_packet_compare (pkbuf1, pkbuf2);
}

int
hicn_interest_get_lifetime (const hicn_packet_buffer_t *pkbuf,
			    hicn_lifetime_t *lifetime)
{
  return hicn_packet_get_lifetime (pkbuf, lifetime);
}

int
hicn_interest_set_lifetime (const hicn_packet_buffer_t *pkbuf,
			    hicn_lifetime_t lifetime)
{
  return hicn_packet_set_lifetime (pkbuf, lifetime);
}

int
hicn_interest_get_payload (const hicn_packet_buffer_t *pkbuf, u8 **payload,
			   size_t *payload_size, bool hard_copy)
{
  return hicn_packet_get_payload (pkbuf, payload, payload_size, hard_copy);
}

int
hicn_interest_set_payload (const hicn_packet_buffer_t *pkbuf,
			   const u8 *payload, size_t payload_len)
{
  return hicn_packet_set_payload (pkbuf, payload, (u16) payload_len);
}

int
hicn_interest_reset_for_hash (hicn_packet_buffer_t *pkbuf)
{
  return CALL (reset_interest_for_hash, pkbuf);
}

/* Data */

int
hicn_data_get_name (const hicn_packet_buffer_t *pkbuf, hicn_name_t *name)
{
  return CALL (get_data_name, pkbuf, name);
}

int
hicn_data_set_name (const hicn_packet_buffer_t *pkbuf, const hicn_name_t *name)
{
  return CALL (set_data_name, pkbuf, name);
}

int
hicn_data_get_locator (const hicn_packet_buffer_t *pkbuf,
		       hicn_ip_address_t *address)
{
  return CALL (get_data_locator, pkbuf, address);
}

int
hicn_data_set_locator (const hicn_packet_buffer_t *pkbuf,
		       const hicn_ip_address_t *address)
{
  return CALL (set_data_locator, pkbuf, address);
}

int
hicn_data_compare (const hicn_packet_buffer_t *pkbuf1,
		   const hicn_packet_buffer_t *pkbuf2)
{
  return hicn_packet_compare (pkbuf1, pkbuf2);
}

int
hicn_data_get_expiry_time (const hicn_packet_buffer_t *pkbuf,
			   hicn_lifetime_t *expiry_time)
{
  return hicn_packet_get_lifetime (pkbuf, expiry_time);
}

int
hicn_data_set_expiry_time (const hicn_packet_buffer_t *pkbuf,
			   hicn_lifetime_t expiry_time)
{
  return hicn_packet_set_lifetime (pkbuf, expiry_time);
}

/* Path label */

int
hicn_data_get_path_label (const hicn_packet_buffer_t *pkbuf,
			  hicn_path_label_t *path_label)
{
  return CALL (get_data_path_label, pkbuf, path_label);
}

int
hicn_get_path_label (const hicn_packet_buffer_t *pkbuf,
		     hicn_path_label_t *path_label)
{
  if (!hicn_packet_is_data (pkbuf))
    return INVALID_PATH_LABEL;
  return hicn_data_get_path_label (pkbuf, path_label);
}

int
hicn_data_set_path_label (const hicn_packet_buffer_t *pkbuf,
			  hicn_path_label_t path_label)
{
  return CALL (set_data_path_label, pkbuf, path_label);
}

int
hicn_data_set_payload (const hicn_packet_buffer_t *pkbuf, const u8 *payload,
		       size_t payload_len)
{
  return hicn_packet_set_payload (pkbuf, payload, (u16) payload_len);
}

int
hicn_data_get_payload (const hicn_packet_buffer_t *pkbuf, u8 **payload,
		       size_t *payload_size, bool hard_copy)
{
  return hicn_packet_get_payload (pkbuf, payload, payload_size, hard_copy);
}

int
hicn_data_reset_for_hash (hicn_packet_buffer_t *pkbuf)
{
  return CALL (reset_data_for_hash, pkbuf);
}

int
hicn_data_is_last (const hicn_packet_buffer_t *pkbuf, int *is_last)
{
  return CALL (is_last_data, pkbuf, is_last);
}

int
hicn_data_set_last (const hicn_packet_buffer_t *pkbuf)
{
  return CALL (set_last_data, pkbuf);
}

int
hicn_packet_get_signature (const hicn_packet_buffer_t *pkbuf,
			   uint8_t **sign_buf)
{
  return CALL (get_signature, pkbuf, sign_buf);
}

int
hicn_packet_get_ttl (const hicn_packet_buffer_t *pkbuf, u8 *hops)
{
  return CALL (get_ttl, pkbuf, hops);
}

int
hicn_packet_set_ttl (const hicn_packet_buffer_t *pkbuf, u8 hops)
{
  return CALL (set_ttl, pkbuf, hops);
}

int
hicn_packet_get_src_port (const hicn_packet_buffer_t *pkbuf, u16 *port)
{
  return CALL (get_src_port, pkbuf, port);
}

int
hicn_packet_set_src_port (const hicn_packet_buffer_t *pkbuf, u16 port)
{
  return CALL (set_src_port, pkbuf, port);
}

int
hicn_packet_get_dst_port (const hicn_packet_buffer_t *pkbuf, u16 *port)
{
  return CALL (get_dst_port, pkbuf, port);
}

int
hicn_packet_set_dst_port (const hicn_packet_buffer_t *pkbuf, u16 port)
{
  return CALL (set_dst_port, pkbuf, port);
}

int
hicn_interest_rewrite (const hicn_packet_buffer_t *pkbuf,
		       const hicn_ip_address_t *addr_new,
		       hicn_ip_address_t *addr_old)
{
  return CALL (rewrite_interest, pkbuf, addr_new, addr_old);
}

int
hicn_data_rewrite (const hicn_packet_buffer_t *pkbuf,
		   const hicn_ip_address_t *addr_new,
		   hicn_ip_address_t *addr_old, const hicn_faceid_t face_id,
		   u8 reset_pl)
{
  return CALL (rewrite_data, pkbuf, addr_new, addr_old, face_id, reset_pl);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
