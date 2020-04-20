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
 * @file protocol/ipv4.c
 * @brief hICN operations for IPv4 header
 *
 * NOTE: IPv4 options (affecting the header size) are currently not supported.
 */

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#include <stdlib.h>
#include <string.h>

#include <hicn/error.h>
#include <hicn/ops.h>
#include <hicn/common.h>
#include <hicn/header.h>

#include <hicn/protocol/ipv4.h>

int ipv4_get_payload_length (hicn_type_t type, const hicn_protocol_t * h,
			     size_t * payload_length);

int
ipv4_init_packet_header (hicn_type_t type, hicn_protocol_t * h)
{
  size_t total_header_length;
  int rc =
    hicn_ops_vft[type.l1]->get_header_length (type, h, &total_header_length);
  if (rc < 0)
    return rc;

  h->ipv4 = (_ipv4_header_t)
  {
  .version_ihl =
      (IPV4_DEFAULT_VERSION << 4) | (0x0f & IPV4_DEFAULT_IHL),.tos =
      IPV4_DEFAULT_TOS,.len = htons ((u16) total_header_length),.id =
      htons (IPV4_DEFAULT_ID),.frag_off =
      htons (IPV4_DEFAULT_FRAG_OFF),.ttl = HICN_DEFAULT_TTL,.protocol =
      type.l2,.csum = 0,.saddr.as_u32 = 0,.daddr.as_u32 = 0,};

  return CHILD_OPS (init_packet_header, type, h);
}

int
ipv4_get_interest_locator (hicn_type_t type, const hicn_protocol_t * h,
			   ip46_address_t * ip_address)
{
  ip_address->ip4 = h->ipv4.saddr;
  return HICN_LIB_ERROR_NONE;
}

int
ipv4_set_interest_locator (hicn_type_t type, hicn_protocol_t * h,
			   const ip46_address_t * ip_address)
{
  h->ipv4.saddr = ip_address->ip4;
  return HICN_LIB_ERROR_NONE;
}

int
ipv4_get_interest_name (hicn_type_t type, const hicn_protocol_t * h,
			hicn_name_t * name)
{
  name->prefix.ip4.as_u32 = h->ipv4.daddr.as_u32;
  return CHILD_OPS (get_interest_name_suffix, type, h, &(name->suffix));
}

int
ipv4_set_interest_name (hicn_type_t type, hicn_protocol_t * h,
			const hicn_name_t * name)
{
  h->ipv4.daddr.as_u32 = name->prefix.ip4.as_u32;
  return CHILD_OPS (set_interest_name_suffix, type, h, &(name->suffix));
}

int
ipv4_get_interest_name_suffix (hicn_type_t type, const hicn_protocol_t * h,
			       hicn_name_suffix_t * suffix)
{
  return CHILD_OPS (get_interest_name_suffix, type, h, suffix);
}

int
ipv4_set_interest_name_suffix (hicn_type_t type, hicn_protocol_t * h,
			       const hicn_name_suffix_t * suffix)
{
  return CHILD_OPS (set_interest_name_suffix, type, h, suffix);
}

int
ipv4_reset_interest_for_hash (hicn_type_t type, hicn_protocol_t * h)
{
  /* Sets everything to 0 up to IP destination address */
  memset (&(h->ipv4), 0, 16);

  return CHILD_OPS (reset_interest_for_hash, type, h);
}

int
ipv4_get_data_locator (hicn_type_t type, const hicn_protocol_t * h,
		       ip46_address_t * ip_address)
{
  ip_address->ip4 = h->ipv4.daddr;
  return HICN_LIB_ERROR_NONE;
}

int
ipv4_set_data_locator (hicn_type_t type, hicn_protocol_t * h,
		       const ip46_address_t * ip_address)
{
  h->ipv4.daddr = ip_address->ip4;
  return HICN_LIB_ERROR_NONE;
}

int
ipv4_get_data_name (hicn_type_t type, const hicn_protocol_t * h,
		    hicn_name_t * name)
{
  name->prefix.ip4.as_u32 = h->ipv4.saddr.as_u32;
  return CHILD_OPS (get_data_name_suffix, type, h, &(name->suffix));
}

int
ipv4_set_data_name (hicn_type_t type, hicn_protocol_t * h,
		    const hicn_name_t * name)
{
  h->ipv4.saddr.as_u32 = name->prefix.ip4.as_u32;
  return CHILD_OPS (set_data_name_suffix, type, h, &(name->suffix));
}

int
ipv4_get_data_name_suffix (hicn_type_t type, const hicn_protocol_t * h,
			   hicn_name_suffix_t * suffix)
{
  return CHILD_OPS (get_data_name_suffix, type, h, suffix);
}

int
ipv4_set_data_name_suffix (hicn_type_t type, hicn_protocol_t * h,
			   const hicn_name_suffix_t * suffix)
{
  return CHILD_OPS (set_data_name_suffix, type, h, suffix);
}

int
ipv4_get_data_pathlabel (hicn_type_t type, const hicn_protocol_t * h,
			 u32 * pathlabel)
{
  return CHILD_OPS (get_data_pathlabel, type, h, pathlabel);
}

int
ipv4_set_data_pathlabel (hicn_type_t type, hicn_protocol_t * h,
			 const u32 pathlabel)
{
  return CHILD_OPS (set_data_pathlabel, type, h, pathlabel);
}

int
ipv4_update_data_pathlabel (hicn_type_t type, hicn_protocol_t * h,
			    const hicn_faceid_t face_id)
{
  return CHILD_OPS (update_data_pathlabel, type, h, face_id);
}

int
ipv4_reset_data_for_hash (hicn_type_t type, hicn_protocol_t * h)
{
  /* Sets everything to 0 up to source address */
  memset (&h->ipv4, 0, 12);
  /* Clears destination address */
  memset (&(h->ipv4.daddr), 0, 4);

  return CHILD_OPS (reset_data_for_hash, type, h);
}

int
ipv4_get_lifetime (hicn_type_t type, const hicn_protocol_t * h,
		   hicn_lifetime_t * lifetime)
{
  return CHILD_OPS (get_lifetime, type, h, lifetime);
}

int
ipv4_set_lifetime (hicn_type_t type, hicn_protocol_t * h,
		   const hicn_lifetime_t lifetime)
{
  return CHILD_OPS (set_lifetime, type, h, lifetime);
}

int
ipv4_update_checksums (hicn_type_t type, hicn_protocol_t * h,
		       u16 partial_csum, size_t payload_length)
{
  /*
   * Checksum field is not accounted for in lower layers, so we can compute
   * them in any order. Note that it is only a header checksum.
   */
  h->ipv4.csum = 0;
  h->ipv4.csum = csum (h, IPV4_HDRLEN, 0);

  /* Retrieve payload length if not specified, as it is not available later */
  if (payload_length == 0)
    {
      int rc = ipv4_get_payload_length (type, h, &payload_length);
      if (rc < 0)
	return rc;
    }

  /* Ignore the payload if payload_length = ~0 */
  if (payload_length == ~0)
    {
      payload_length = 0;
    }

  /* Build pseudo-header */
  ipv4_pseudo_header_t psh;
  psh.ip_src = h->ipv4.saddr;
  psh.ip_dst = h->ipv4.daddr;
  /* Size is u32 and not u16, we cannot copy and need to care about endianness */
  psh.size = htons (ntohs (h->ipv4.len) - (u16) IPV4_HDRLEN);
  psh.zero = 0;
  psh.protocol = (u8) h->ipv4.protocol;

  /* Compute partial checksum based on pseudo-header */
  if (partial_csum != 0)
    {
      partial_csum = ~partial_csum;
    }
  partial_csum = csum (&psh, IPV4_PSHDRLEN, partial_csum);

  return CHILD_OPS (update_checksums, type, h, partial_csum, payload_length);
}

int
ipv4_verify_checksums (hicn_type_t type, hicn_protocol_t * h,
		       u16 partial_csum, size_t payload_length)
{
  /*
   * Checksum field is not accounted for in lower layers, so we can compute
   * them in any order. Note that it is only a header checksum.
   */
  if (csum (h, IPV4_HDRLEN, 0) != 0)
    return HICN_LIB_ERROR_CORRUPTED_PACKET;

  /* Retrieve payload length if not specified, as it is not available later */
  if (payload_length == 0)
    {
      int rc = ipv4_get_payload_length (type, h, &payload_length);
      if (rc < 0)
	return rc;
    }

  /* Build pseudo-header */
  ipv4_pseudo_header_t psh;
  psh.ip_src = h->ipv4.saddr;
  psh.ip_dst = h->ipv4.daddr;
  /* Size is u32 and not u16, we cannot copy and need to care about endianness */
  psh.size = htons (ntohs (h->ipv4.len) - (u16) IPV4_HDRLEN);
  psh.zero = 0;
  psh.protocol = (u8) h->ipv4.protocol;

  /* Compute partial checksum based on pseudo-header */
  partial_csum = csum (&psh, IPV4_PSHDRLEN, 0);

  return CHILD_OPS (update_checksums, type, h, partial_csum, payload_length);
}

int
ipv4_rewrite_interest (hicn_type_t type, hicn_protocol_t * h,
		       const ip46_address_t * addr_new,
		       ip46_address_t * addr_old)
{
  // ASSERT(addr_old == NULL);
  addr_old->ip4 = h->ipv4.saddr;
  addr_old->pad[0] = 0;
  addr_old->pad[1] = 0;
  addr_old->pad[2] = 0;

  h->ipv4.saddr = addr_new->ip4;
  h->ipv4.csum = 0;
  h->ipv4.csum = csum (&h->ipv4, IPV4_HDRLEN, 0);

  return CHILD_OPS (rewrite_interest, type, h, addr_new, addr_old);
}

int
ipv4_rewrite_data (hicn_type_t type, hicn_protocol_t * h,
		   const ip46_address_t * addr_new, ip46_address_t * addr_old,
		   const hicn_faceid_t face_id)
{
  // ASSERT(addr_old == NULL);
  addr_old->ip4 = h->ipv4.daddr;
  addr_old->pad[0] = 0;
  addr_old->pad[1] = 0;
  addr_old->pad[2] = 0;

  h->ipv4.daddr = addr_new->ip4;
  h->ipv4.csum = 0;
  h->ipv4.csum = csum (&h->ipv4, IPV4_HDRLEN, 0);

  return CHILD_OPS (rewrite_data, type, h, addr_new, addr_old, face_id);
}

int
ipv4_get_current_length (hicn_type_t type, const hicn_protocol_t * h,
			 size_t * header_length)
{
  *header_length = IPV4_HDRLEN;
  return HICN_LIB_ERROR_NONE;
}

int
ipv4_get_length (hicn_type_t type, const hicn_protocol_t * h,
		 size_t * header_length)
{
  *header_length = h->ipv4.len;
  return HICN_LIB_ERROR_NONE;
}

int
ipv4_get_current_header_length (hicn_type_t type, const hicn_protocol_t * h,
				size_t * header_length)
{
  *header_length = IPV4_HDRLEN;
  return HICN_LIB_ERROR_NONE;
}

int
ipv4_get_header_length (hicn_type_t type, const hicn_protocol_t * h,
			size_t * header_length)
{
  size_t child_header_length = 0;
  int rc = CHILD_OPS (get_header_length, type, h, &child_header_length);
  if (rc < 0)
    return rc;
  *header_length = IPV4_HDRLEN + child_header_length;
  return HICN_LIB_ERROR_NONE;
}

int
ipv4_get_payload_length (hicn_type_t type, const hicn_protocol_t * h,
			 size_t * payload_length)
{
  size_t child_header_length;
  int rc = CHILD_OPS (get_header_length, type, h, &child_header_length);
  if (rc < 0)
    return rc;
  *payload_length = htons (h->ipv4.len) - IPV4_HDRLEN - child_header_length;
  return HICN_LIB_ERROR_NONE;
}

int
ipv4_set_payload_length (hicn_type_t type, hicn_protocol_t * h,
			 size_t payload_length)
{
  size_t child_header_length;
  int rc = CHILD_OPS (get_header_length, type, h, &child_header_length);
  if (rc < 0)
    return rc;
  h->ipv4.len = htons ((u_short) (payload_length + IPV4_HDRLEN + child_header_length));
  return HICN_LIB_ERROR_NONE;
}

int
ipv4_get_signature_size (hicn_type_t type, const hicn_protocol_t * h,
			 size_t * signature_size)
{
  return CHILD_OPS (get_signature_size, type, h, signature_size);
}

int
ipv4_set_signature_size (hicn_type_t type, hicn_protocol_t * h,
			 size_t signature_size)
{
  return CHILD_OPS (set_signature_size, type, h, signature_size);
}

int
ipv4_set_signature_timestamp(hicn_type_t type, hicn_protocol_t * h,
       uint64_t signature_timestamp)
{
  return CHILD_OPS (set_signature_timestamp, type, h, signature_timestamp);
}

int
ipv4_get_signature_timestamp (hicn_type_t type, const hicn_protocol_t * h,
       uint64_t * signature_timestamp)
{
  return CHILD_OPS (get_signature_timestamp, type, h, signature_timestamp);
}

int
ipv4_set_validation_algorithm (hicn_type_t type, hicn_protocol_t * h,
       uint8_t validation_algorithm)
{
  return CHILD_OPS (set_validation_algorithm, type, h, validation_algorithm);
}

int
ipv4_get_validation_algorithm (hicn_type_t type, const hicn_protocol_t * h,
       uint8_t * validation_algorithm)
{
  return CHILD_OPS (get_validation_algorithm, type, h, validation_algorithm);
}

int
ipv4_set_key_id (hicn_type_t type, hicn_protocol_t * h,
       uint8_t *key_id)
{
  return CHILD_OPS (set_key_id, type, h, key_id);
}

int
ipv4_get_key_id (hicn_type_t type, hicn_protocol_t * h,
       uint8_t **key_id, uint8_t *key_id_size)
{
  return CHILD_OPS (get_key_id, type, h, key_id, key_id_size);
}

int
ipv4_get_signature (hicn_type_t type, hicn_protocol_t * h,
		              uint8_t ** signature)
{
  return CHILD_OPS (get_signature, type, h, signature);
}

DECLARE_HICN_OPS (ipv4);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
