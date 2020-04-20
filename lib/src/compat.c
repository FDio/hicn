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
 * @file compat.c
 * @brief Implementation of the compatibility layer.
 */
#ifndef _WIN32
#include <netinet/in.h>
#endif
#include <string.h>		// memset
#include <stddef.h>		// offsetof

#include <hicn/common.h>
#include <hicn/compat.h>
#include <hicn/error.h>
#include <hicn/header.h>
#include <hicn/name.h>
#include <hicn/ops.h>

#define member_size(type, member) sizeof(((type *)0)->member)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))

#define HICN_NAME_COMPONENT_SIZE 2

int
hicn_packet_get_format (const hicn_header_t * h, hicn_format_t * format)
{
  *format = HF_UNSPEC;

  switch (HICN_IP_VERSION (h))
    {
    case 4:
      switch (h->v4.ip.protocol)
	{
	case IPPROTO_TCP:
	  if (h->v4.tcp.flags & AH_FLAG)
	    *format = HF_INET_TCP_AH;
	  else
	    *format = HF_INET_TCP;
	  break;
	case IPPROTO_ICMP:
	  *format = HF_INET_ICMP;
	  break;
	default:
	  return HICN_LIB_ERROR_NOT_HICN;
	}
      break;
    case 6:
      switch (h->v6.ip.nxt)
	{
	case IPPROTO_TCP:
	  if (h->v6.tcp.flags & AH_FLAG)
	    *format = HF_INET6_TCP_AH;
	  else
	    *format = HF_INET6_TCP;
	  break;
	case IPPROTO_ICMPV6:
	  *format = HF_INET6_ICMP;
	  break;
	default:
	  return HICN_LIB_ERROR_NOT_HICN;
	}
      break;
    default:
      return HICN_LIB_ERROR_NOT_HICN;
    }

  return HICN_LIB_ERROR_NONE;
}

/**
 * @brief Convert (former) hICN format into (newer) hICN type
 * @param [in] format - hICN format
 * @return hICN type, all zero'ed if type is unknown
 */
hicn_type_t
hicn_format_to_type (hicn_format_t format)
{
  switch (format)
    {
    case HF_INET_TCP:
      return HICN_TYPE_IPV4_TCP;
    case HF_INET6_TCP:
      return HICN_TYPE_IPV6_TCP;
    case HF_INET_ICMP:
      return HICN_TYPE_IPV4_ICMP;
    case HF_INET6_ICMP:
      return HICN_TYPE_IPV6_ICMP;
    case HF_INET_TCP_AH:
      return HICN_TYPE_IPV4_TCP_AH;
    case HF_INET6_TCP_AH:
      return HICN_TYPE_IPV6_TCP_AH;
    case HF_INET_ICMP_AH:
      return HICN_TYPE_IPV4_ICMP_AH;
    case HF_INET6_ICMP_AH:
      return HICN_TYPE_IPV6_ICMP_AH;
    default:
      break;
    }
  return HICN_TYPE_NONE;
}

/**
 * @brief Parse hICN header and return hICN type
 * @param [in] h - hICN header
 * @param [out] format - hICN type
 * @return hICN error code
 *
 * This function is used to wrap old API calls to new ones
 */
hicn_type_t
hicn_header_to_type (const hicn_header_t * h)
{
  hicn_format_t format;
  hicn_packet_get_format (h, &format);
  return hicn_format_to_type (format);
}

int
hicn_packet_init_header (hicn_format_t format, hicn_header_t * packet)
{
  hicn_type_t type = hicn_format_to_type (format);
  return hicn_ops_vft[type.l1]->init_packet_header (type, &packet->protocol);
}

int
hicn_packet_compute_checksum (hicn_format_t format, hicn_header_t * h)
{
  hicn_type_t type = hicn_format_to_type (format);
  return hicn_ops_vft[type.l1]->update_checksums (type, &h->protocol, 0, 0);
}

int
hicn_packet_compute_header_checksum (hicn_format_t format, hicn_header_t * h,
				     u16 init_sum)
{
  hicn_type_t type = hicn_format_to_type (format);
  /* payload_length == ~0: ignore payload */
  return hicn_ops_vft[type.l1]->update_checksums (type, &h->protocol,
						  init_sum, ~0);
}

int
hicn_packet_check_integrity (hicn_format_t format, hicn_header_t * h)
{
  hicn_type_t type = hicn_format_to_type (format);
  return hicn_ops_vft[type.l1]->verify_checksums (type, &h->protocol, 0, 0);
}

int
hicn_packet_get_header_length_from_format (hicn_format_t format,
					   size_t * header_length)
{
  *header_length = _is_ipv4 (format) * IPV4_HDRLEN;
  *header_length += _is_ipv6 (format) * IPV6_HDRLEN;
  *header_length += _is_icmp (format) * ICMP_HDRLEN;
  *header_length += _is_tcp (format) * TCP_HDRLEN;
  *header_length += _is_ah (format) * AH_HDRLEN;

  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_get_header_length (hicn_format_t format, const hicn_header_t * h,
			       size_t * header_length)
{
  hicn_packet_get_header_length_from_format (format, header_length);
  int is_ah = _is_ah (format);
  int is_ipv4 = _is_ipv4 (format);
  int is_ipv6 = _is_ipv6 (format);
  // The signature payload is expressed as number of 32 bits words
  if (is_ah && is_ipv4)
    *header_length += (h->v4ah.ah.payloadlen) << 2;
  else if(is_ah && is_ipv6)
    *header_length += (h->v6ah.ah.payloadlen) << 2;

  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_get_payload_length (hicn_format_t format, const hicn_header_t * h,
				size_t * payload_length)
{
  hicn_type_t type = hicn_format_to_type (format);
  return hicn_ops_vft[type.l1]->get_payload_length (type, &h->protocol,
						    payload_length);
}

int
hicn_packet_set_payload_length (hicn_format_t format, hicn_header_t * h,
				const size_t payload_length)
{
  hicn_type_t type = hicn_format_to_type (format);
  return hicn_ops_vft[type.l1]->set_payload_length (type, &h->protocol,
						    payload_length);
}

int
hicn_packet_compare (const hicn_header_t * packet1,
		     const hicn_header_t * packet2)
{
  hicn_type_t type1 = hicn_header_to_type (packet1);
  hicn_type_t type2 = hicn_header_to_type (packet2);

  size_t len1, len2;
  int rc;

  if (type1.as_u32 != type2.as_u32)
    return HICN_LIB_ERROR_UNEXPECTED;

  rc = hicn_ops_vft[type1.l1]->get_length (type1, &packet1->protocol, &len1);
  if (PREDICT_FALSE (rc < 0))
    return HICN_LIB_ERROR_UNEXPECTED;

  rc = hicn_ops_vft[type2.l1]->get_length (type2, &packet2->protocol, &len2);
  if (PREDICT_FALSE (rc < 0))
    return HICN_LIB_ERROR_UNEXPECTED;

  if (len1 != len2)
    return HICN_LIB_ERROR_UNEXPECTED;

  return memcmp ((u8 *) packet1, (u8 *) packet2, len1);

}

int
hicn_packet_get_name (hicn_format_t format, const hicn_header_t * h,
		      hicn_name_t * name, u8 is_interest)
{
  hicn_type_t type = hicn_format_to_type (format);

  if (is_interest)
    return hicn_ops_vft[type.l1]->get_interest_name (type, &h->protocol,
						     name);
  else
    return hicn_ops_vft[type.l1]->get_data_name (type, &h->protocol, name);
}

int
hicn_packet_set_name (hicn_format_t format, hicn_header_t * h,
		      const hicn_name_t * name, u8 is_interest)
{
  hicn_type_t type = hicn_format_to_type (format);

  if (is_interest)
    return hicn_ops_vft[type.l1]->set_interest_name (type, &h->protocol,
						     name);
  else
    return hicn_ops_vft[type.l1]->set_data_name (type, &h->protocol, name);
}

int
hicn_packet_set_payload (hicn_format_t format, hicn_header_t * h,
			 const u8 * payload, u16 payload_length)
{
  hicn_type_t type = hicn_format_to_type (format);
  size_t header_length;
  int rc;

  rc =
    hicn_ops_vft[type.l1]->get_header_length (type, &h->protocol,
					      &header_length);
  if (rc < 0)
    return rc;

  memcpy ((u8 *) h + header_length, payload, payload_length);

  return hicn_ops_vft[type.l1]->set_payload_length (type, &h->protocol,
						    payload_length);
}

int
hicn_packet_get_payload (hicn_format_t format, const hicn_header_t * h,
			 u8 ** payload, size_t * payload_size, bool hard_copy)
{
  size_t header_length, payload_length;
  int rc;
  hicn_type_t type = hicn_format_to_type (format);

  rc =
    hicn_ops_vft[type.l1]->get_header_length (type, &h->protocol,
					      &header_length);
  if (rc < 0)
    return rc;

  rc =
    hicn_ops_vft[type.l1]->get_payload_length (type, &h->protocol,
					       &payload_length);
  if (rc < 0)
    return rc;

  if (hard_copy)
    {
      memcpy (payload, (u8 *) h + header_length, payload_length);
    }
  else
    {
      *payload = (u8 *) h + header_length;
    }

  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_get_locator (hicn_format_t format, const hicn_header_t * h,
			 ip_address_t * address, bool is_interest)
{
  int is_ipv4 = (format & HFO_INET);
  int is_ipv6 = (format & HFO_INET6) >> 1;

  if (is_ipv4)
    {
      address->v4.as_inaddr = is_interest
          ? h->v4.ip.saddr.as_inaddr
          : h->v4.ip.daddr.as_inaddr;
    }
  else if (is_ipv6)
    {
      address->v6.as_in6addr = is_interest
          ? h->v6.ip.saddr.as_in6addr
          : h->v6.ip.daddr.as_in6addr;
    }
  else
    {
      return HICN_LIB_ERROR_NOT_IMPLEMENTED;
    }

  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_set_locator (hicn_format_t format, hicn_header_t * h,
			 const ip_address_t * address, bool is_interest)
{
  int is_ipv4 = (format & HFO_INET);
  int is_ipv6 = (format & HFO_INET6) >> 1;

  if (is_ipv6)
    {
        if (is_interest)
            h->v6.ip.saddr.as_in6addr = address->v6.as_in6addr;
        else
            h->v6.ip.daddr.as_in6addr = address->v6.as_in6addr;
    }
  else if (is_ipv4)
    {
        if (is_interest)
            h->v4.ip.saddr.as_inaddr = address->v4.as_inaddr;
        else
            h->v4.ip.daddr.as_inaddr = address->v4.as_inaddr;
    }
  else
    {
      return HICN_LIB_ERROR_INVALID_PARAMETER;
    }

  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_get_signature_size (hicn_format_t format, const hicn_header_t * h,
				size_t * bytes)
{
  hicn_type_t type = hicn_format_to_type (format);
  return hicn_ops_vft[type.l1]->get_signature_size (type, &h->protocol,
						    bytes);
}

int
hicn_packet_set_signature_size (hicn_format_t format, hicn_header_t * h,
				size_t bytes)
{
  hicn_type_t type = hicn_format_to_type (format);
  return hicn_ops_vft[type.l1]->set_signature_size (type, &h->protocol,
						    bytes);
}

int
hicn_packet_set_signature_timestamp (hicn_format_t format, hicn_header_t * h,
				uint64_t signature_timestamp)
{
  hicn_type_t type = hicn_format_to_type (format);
  return hicn_ops_vft[type.l1]->set_signature_timestamp (type, &h->protocol,
						    signature_timestamp);
}

int
hicn_packet_get_signature_timestamp (hicn_format_t format, const hicn_header_t * h,
				uint64_t *signature_timestamp)
{
  hicn_type_t type = hicn_format_to_type (format);
  return hicn_ops_vft[type.l1]->get_signature_timestamp (type, &h->protocol,
						    signature_timestamp);
}

int
hicn_packet_set_validation_algorithm (hicn_format_t format, hicn_header_t * h,
				uint8_t validation_algorithm)
{
  hicn_type_t type = hicn_format_to_type (format);
  return hicn_ops_vft[type.l1]->set_validation_algorithm (type, &h->protocol,
						    validation_algorithm);
}

int
hicn_packet_get_validation_algorithm (hicn_format_t format, const hicn_header_t * h,
				uint8_t * validation_algorithm)
{
  hicn_type_t type = hicn_format_to_type (format);
  return hicn_ops_vft[type.l1]->get_validation_algorithm (type, &h->protocol,
						    validation_algorithm);
}

int
hicn_packet_set_key_id (hicn_format_t format, hicn_header_t * h,
				uint8_t *key_id)
{
  hicn_type_t type = hicn_format_to_type (format);
  return hicn_ops_vft[type.l1]->set_key_id (type, &h->protocol,
						    key_id);
}

int
hicn_packet_get_key_id (hicn_format_t format, hicn_header_t * h,
				uint8_t ** key_id, uint8_t *key_id_length)
{
  hicn_type_t type = hicn_format_to_type (format);
  return hicn_ops_vft[type.l1]->get_key_id (type, &h->protocol,
						    key_id, key_id_length);
}

int
hicn_packet_get_hoplimit (const hicn_header_t * h, u8 * hops)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      *hops = h->v6.ip.hlim;
      break;
    case 4:
      *hops = h->v4.ip.ttl;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }

  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_set_hoplimit (hicn_header_t * h, u8 hops)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      h->v6.ip.hlim = hops;
      break;
    case 4:
      h->v4.ip.ttl = hops;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }

  return HICN_LIB_ERROR_NONE;
}


int
hicn_packet_get_lifetime (const hicn_header_t * h, u32 * lifetime)
{
  hicn_type_t type = hicn_header_to_type (h);
  return hicn_ops_vft[type.l1]->get_lifetime (type, &h->protocol,
					      (hicn_lifetime_t *) lifetime);
}

int
hicn_packet_set_lifetime (hicn_header_t * h, u32 lifetime)
{
  hicn_type_t type = hicn_header_to_type (h);
  return hicn_ops_vft[type.l1]->set_lifetime (type, &h->protocol,
					      (hicn_lifetime_t) lifetime);
}

int
hicn_packet_get_reserved_bits (const hicn_header_t * h, u8 * reserved_bits)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      *reserved_bits = (u8)(h->v6.tcp.reserved);
      break;
    case 4:
      *reserved_bits = (u8)(h->v4.tcp.reserved);
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }

  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_set_reserved_bits (hicn_header_t * h, const u8 reserved_bits)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      h->v6.tcp.reserved = reserved_bits;
      break;
    case 4:
      h->v4.tcp.reserved = reserved_bits;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }

  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_get_payload_type (const hicn_header_t * h,
			      hicn_payload_type_t * payload_type)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      *payload_type = ((h->v6.tcp.flags & HICN_TCP_FLAG_URG) == HICN_TCP_FLAG_URG);
      break;
    case 4:
      *payload_type = ((h->v4.tcp.flags & HICN_TCP_FLAG_URG) == HICN_TCP_FLAG_URG);
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }

  if (*payload_type == HPT_UNSPEC)
    {
      return HICN_LIB_ERROR_UNEXPECTED;
    }

  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_set_payload_type (hicn_header_t * h,
			      hicn_payload_type_t payload_type)
{
  if (payload_type != HPT_DATA && payload_type != HPT_MANIFEST)
    {
      return HICN_LIB_ERROR_UNEXPECTED;
    }

  switch (HICN_IP_VERSION (h))
    {
    case 6:
      if (payload_type)
	h->v6.tcp.flags = h->v6.tcp.flags | HICN_TCP_FLAG_URG;
      else
	h->v6.tcp.flags = h->v6.tcp.flags & ~HICN_TCP_FLAG_URG;
      break;
    case 4:
      if (payload_type)
	h->v4.tcp.flags = h->v4.tcp.flags | HICN_TCP_FLAG_URG;
      else
	h->v4.tcp.flags = h->v4.tcp.flags & ~HICN_TCP_FLAG_URG;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }

  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_set_syn (hicn_header_t * h)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      h->v6.tcp.flags = h->v6.tcp.flags | HICN_TCP_FLAG_SYN;
      break;
    case 4:
      h->v4.tcp.flags = h->v4.tcp.flags | HICN_TCP_FLAG_SYN;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_reset_syn (hicn_header_t * h)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      h->v6.tcp.flags = h->v6.tcp.flags & ~HICN_TCP_FLAG_SYN;
      break;
    case 4:
      h->v4.tcp.flags = h->v4.tcp.flags & ~HICN_TCP_FLAG_SYN;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_test_syn (const hicn_header_t * h, bool * flag)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      *flag = h->v6.tcp.flags & HICN_TCP_FLAG_SYN;
      break;
    case 4:
      *flag = h->v4.tcp.flags & HICN_TCP_FLAG_SYN;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_set_ack (hicn_header_t * h)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      h->v6.tcp.flags = h->v6.tcp.flags | HICN_TCP_FLAG_ACK;
      break;
    case 4:
      h->v4.tcp.flags = h->v4.tcp.flags | HICN_TCP_FLAG_ACK;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_reset_ack (hicn_header_t * h)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      h->v6.tcp.flags = h->v6.tcp.flags & ~HICN_TCP_FLAG_ACK;
      break;
    case 4:
      h->v4.tcp.flags = h->v4.tcp.flags & ~HICN_TCP_FLAG_ACK;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_test_ack (const hicn_header_t * h, bool * flag)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      *flag = h->v6.tcp.flags & HICN_TCP_FLAG_ACK;
      break;
    case 4:
      *flag = h->v4.tcp.flags & HICN_TCP_FLAG_ACK;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_set_rst (hicn_header_t * h)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      h->v6.tcp.flags = h->v6.tcp.flags | HICN_TCP_FLAG_RST;
      break;
    case 4:
      h->v4.tcp.flags = h->v4.tcp.flags | HICN_TCP_FLAG_RST;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_reset_rst (hicn_header_t * h)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      h->v6.tcp.flags = h->v6.tcp.flags & ~HICN_TCP_FLAG_RST;
      break;
    case 4:
      h->v4.tcp.flags = h->v4.tcp.flags & ~HICN_TCP_FLAG_RST;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_test_rst (const hicn_header_t * h, bool * flag)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      *flag = h->v6.tcp.flags & HICN_TCP_FLAG_RST;
      break;
    case 4:
      *flag = h->v4.tcp.flags & HICN_TCP_FLAG_RST;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_set_fin (hicn_header_t * h)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      h->v6.tcp.flags = h->v6.tcp.flags | HICN_TCP_FLAG_FIN;
      break;
    case 4:
      h->v4.tcp.flags = h->v4.tcp.flags | HICN_TCP_FLAG_FIN;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_reset_fin (hicn_header_t * h)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      h->v6.tcp.flags = h->v6.tcp.flags & ~HICN_TCP_FLAG_FIN;
      break;
    case 4:
      h->v4.tcp.flags = h->v4.tcp.flags & ~HICN_TCP_FLAG_FIN;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_test_fin (const hicn_header_t * h, bool * flag)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      *flag = h->v6.tcp.flags & HICN_TCP_FLAG_FIN;
      break;
    case 4:
      *flag = h->v4.tcp.flags & HICN_TCP_FLAG_FIN;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_set_ece (hicn_header_t * h)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      h->v6.tcp.flags = h->v6.tcp.flags | HICN_TCP_FLAG_ECE;
      break;
    case 4:
      h->v4.tcp.flags = h->v4.tcp.flags | HICN_TCP_FLAG_ECE;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_reset_ece (hicn_header_t * h)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      h->v6.tcp.flags = h->v6.tcp.flags & ~HICN_TCP_FLAG_ECE;
      break;
    case 4:
      h->v4.tcp.flags = h->v4.tcp.flags & ~HICN_TCP_FLAG_ECE;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_test_ece (const hicn_header_t * h, bool * flag)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      *flag = h->v6.tcp.flags & HICN_TCP_FLAG_ECE;
      break;
    case 4:
      *flag = h->v4.tcp.flags & HICN_TCP_FLAG_ECE;
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_set_src_port (hicn_header_t * h, u16 src_port)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      h->v6.tcp.sport = htons (src_port);
      break;
    case 4:
      h->v4.tcp.sport = htons (src_port);
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_get_src_port (const hicn_header_t * h, u16 * src_port)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      *src_port = ntohs (h->v6.tcp.sport);
      break;
    case 4:
      *src_port = ntohs (h->v4.tcp.sport);
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_set_dst_port (hicn_header_t * h, u16 dst_port)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      h->v6.tcp.dport = htons (dst_port);
      break;
    case 4:
      h->v4.tcp.dport = htons (dst_port);
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_get_dst_port (const hicn_header_t * h, u16 * dst_port)
{
  switch (HICN_IP_VERSION (h))
    {
    case 6:
      *dst_port = ntohs (h->v6.tcp.dport);
      break;
    case 4:
      *dst_port = ntohs (h->v4.tcp.dport);
      break;
    default:
      return HICN_LIB_ERROR_UNEXPECTED;
    }
  return HICN_LIB_ERROR_NONE;
}

int
hicn_packet_copy_header (hicn_format_t format, const hicn_header_t * packet,
			 hicn_header_t * destination, bool copy_ah)
{
  size_t header_length = _is_ipv4 (format) * IPV4_HDRLEN;
  header_length += _is_ipv6 (format) * IPV6_HDRLEN;
  header_length += _is_icmp (format) * ICMP_HDRLEN;
  header_length += _is_tcp (format) * TCP_HDRLEN;
  header_length += _is_ah (format) * copy_ah * AH_HDRLEN;

  memcpy (destination, packet, header_length);

  return HICN_LIB_ERROR_NONE;
}

#define _INTEREST 1
#define _DATA     0

/* Interest */

int
hicn_interest_get_name (hicn_format_t format, const hicn_header_t * interest,
			hicn_name_t * name)
{
  return hicn_packet_get_name (format, interest, name, _INTEREST);
}

int
hicn_interest_set_name (hicn_format_t format, hicn_header_t * interest,
			const hicn_name_t * name)
{
  int ret_err = hicn_packet_reset_ece (interest);	//interest packet -> ece flag unset
  if (ret_err < 0)
    return HICN_LIB_ERROR_UNEXPECTED;
  return hicn_packet_set_name (format, interest, name, _INTEREST);
}

int
hicn_interest_get_locator (hicn_format_t format,
			   const hicn_header_t * interest,
			   ip_address_t * address)
{
  return hicn_packet_get_locator (format, interest, address, _INTEREST);
}

int
hicn_interest_set_locator (hicn_format_t format, hicn_header_t * interest,
			   const ip_address_t * address)
{
  return hicn_packet_set_locator (format, interest, address, _INTEREST);
}

int
hicn_interest_compare (const hicn_header_t * interest_1,
		       const hicn_header_t * interest_2)
{
  return hicn_packet_compare (interest_1, interest_2);
}

int
hicn_interest_get_lifetime (const hicn_header_t * interest, u32 * lifetime)
{
  return hicn_packet_get_lifetime (interest, lifetime);
}

int
hicn_interest_set_lifetime (hicn_header_t * interest, u32 lifetime)
{
  return hicn_packet_set_lifetime (interest, lifetime);
}

int
hicn_interest_get_header_length (hicn_format_t format,
				 const hicn_header_t * interest,
				 size_t * header_length)
{
  return hicn_packet_get_header_length (format, interest, header_length);
}

int
hicn_interest_get_payload_length (hicn_format_t format,
				  const hicn_header_t * interest,
				  size_t * payload_length)
{
  return hicn_packet_get_payload_length (format, interest, payload_length);
}

int
hicn_interest_get_payload (hicn_format_t format,
			   const hicn_header_t * interest, u8 ** payload,
			   size_t * payload_size, bool hard_copy)
{
  return hicn_packet_get_payload (format, interest, payload, payload_size,
				  hard_copy);
}

int
hicn_interest_set_payload (hicn_format_t format, hicn_header_t * interest,
			   const u8 * payload, size_t payload_length)
{
  return hicn_packet_set_payload (format, interest, payload, (u16)payload_length);
}

int
hicn_interest_reset_for_hash (hicn_format_t format, hicn_header_t * packet)
{
  hicn_type_t type = hicn_format_to_type (format);
  return hicn_ops_vft[type.l1]->reset_interest_for_hash (type,
							 &packet->protocol);
}

/* Data */

int
hicn_data_get_name (hicn_format_t format, const hicn_header_t * data,
		    hicn_name_t * name)
{
  return hicn_packet_get_name (format, data, name, _DATA);
}

int
hicn_data_set_name (hicn_format_t format, hicn_header_t * data,
		    const hicn_name_t * name)
{
  int ret_err = hicn_packet_set_ece (data);	//data packet -> ece flag set
  if (ret_err < 0)
    return HICN_LIB_ERROR_UNEXPECTED;
  return hicn_packet_set_name (format, data, name, _DATA);
}

int
hicn_data_get_locator (hicn_format_t format, const hicn_header_t * data,
		       ip_address_t * address)
{
  return hicn_packet_get_locator (format, data, address, _DATA);
}

int
hicn_data_set_locator (hicn_format_t format, hicn_header_t * data,
		       const ip_address_t * address)
{
  return hicn_packet_set_locator (format, data, address, _DATA);
}

int
hicn_data_compare (const hicn_header_t * data_1, const hicn_header_t * data_2)
{
  return hicn_packet_compare (data_1, data_2);
}

int
hicn_data_get_expiry_time (const hicn_header_t * data, u32 * expiry_time)
{
  return hicn_packet_get_lifetime (data, expiry_time);
}

int
hicn_data_set_expiry_time (hicn_header_t * data, u32 expiry_time)
{
  return hicn_packet_set_lifetime (data, (hicn_lifetime_t) expiry_time);
}

int
hicn_data_get_header_length (hicn_format_t format, hicn_header_t * data,
			     size_t * header_length)
{
  return hicn_packet_get_header_length (format, data, header_length);
}

int
hicn_data_get_payload_length (hicn_format_t format,
			      const hicn_header_t * data,
			      size_t * payload_length)
{
  return hicn_packet_get_payload_length (format, data, payload_length);
}

int
hicn_data_set_payload_type (hicn_header_t * data,
			    hicn_payload_type_t payload_type)
{
  return hicn_packet_set_payload_type (data, payload_type);
}

int
hicn_data_get_payload_type (const hicn_header_t * data,
			    hicn_payload_type_t * payload_type)
{
  return hicn_packet_get_payload_type (data, payload_type);
}

int
hicn_data_get_path_label (const hicn_header_t * data, u32 * path_label)
{
  hicn_type_t type = hicn_header_to_type (data);
  return hicn_ops_vft[type.l1]->get_data_pathlabel (type, &data->protocol,
						    path_label);
}

int
hicn_data_set_path_label (hicn_header_t * data, u32 path_label)
{
  hicn_type_t type = hicn_header_to_type (data);
  return hicn_ops_vft[type.l1]->set_data_pathlabel (type, &data->protocol,
						    path_label);
}

int
hicn_data_set_payload (hicn_format_t format, hicn_header_t * data,
		       const u8 * payload, size_t payload_length)
{
  return hicn_packet_set_payload (format, data, payload, (u16)payload_length);
}

int
hicn_data_get_payload (hicn_format_t format, const hicn_header_t * data,
		       u8 ** payload, size_t * payload_size, bool hard_copy)
{
  return hicn_packet_get_payload (format, data, payload, payload_size,
				  hard_copy);
}

int
hicn_data_reset_for_hash (hicn_format_t format, hicn_header_t * packet)
{
  hicn_type_t type = hicn_format_to_type (format);
  return hicn_ops_vft[type.l1]->reset_data_for_hash (type,
							 &packet->protocol);

}

int hicn_packet_get_signature(hicn_format_t format, hicn_header_t * packet, uint8_t ** sign_buf)
{
  hicn_type_t type = hicn_format_to_type (format);
  return hicn_ops_vft[type.l1]->get_signature (type,
							 &packet->protocol, sign_buf);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
