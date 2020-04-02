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

#include <stdlib.h>
#include <string.h>

#include <hicn/common.h>
#include <hicn/error.h>
#include <hicn/ops.h>

int
ipv6_get_payload_length (hicn_type_t type, const hicn_protocol_t * h,
			 size_t * payload_length);

int
ipv6_init_packet_header (hicn_type_t type, hicn_protocol_t * h)
{
  size_t total_header_length;
  int rc = CHILD_OPS (get_header_length, type, h, &total_header_length);
  if (rc < 0)
    return rc;

  /* *INDENT-OFF* */
  h->ipv6 = (_ipv6_header_t)
  {
    .saddr = {{ 0 }}
    ,.daddr = {{ 0 }}
    ,.version_class_flow = htonl ((IPV6_DEFAULT_VERSION << 28) |
				  (IPV6_DEFAULT_TRAFFIC_CLASS << 20) |
				  (IPV6_DEFAULT_FLOW_LABEL & 0xfffff)),
    .len = htons ((u16) total_header_length),
    .nxt = type.l2,
    .hlim = HICN_DEFAULT_TTL,
  };
  /* *INDENT-ON* */
  return CHILD_OPS (init_packet_header, type, h);
}

int
ipv6_get_interest_locator (hicn_type_t type, const hicn_protocol_t * h,
			   ip46_address_t * ip_address)
{
  ip_address->ip6 = h->ipv6.saddr;
  return HICN_LIB_ERROR_NONE;
}

int
ipv6_set_interest_locator (hicn_type_t type, hicn_protocol_t * h,
			   const ip46_address_t * ip_address)
{
  h->ipv6.saddr = ip_address->ip6;
  return HICN_LIB_ERROR_NONE;
}

int
ipv6_get_interest_name (hicn_type_t type, const hicn_protocol_t * h,
			hicn_name_t * name)
{
  name->ip6.prefix_as_ip6 = h->ipv6.daddr;
#ifndef HICN_VPP_PLUGIN
  name->type = HNT_CONTIGUOUS_V6;
  name->len = HICN_V6_NAME_LEN;
#endif /* HICN_VPP_PLUGIN */
  return CHILD_OPS (get_interest_name_suffix, type, h, &(name->ip6.suffix));
}

int
ipv6_set_interest_name (hicn_type_t type, hicn_protocol_t * h,
			const hicn_name_t * name)
{
  h->ipv6.daddr = name->ip6.prefix_as_ip6;
  return CHILD_OPS (set_interest_name_suffix, type, h, &(name->ip6.suffix));
}

int
ipv6_get_interest_name_suffix (hicn_type_t type, const hicn_protocol_t * h,
			       hicn_name_suffix_t * suffix)
{
  return CHILD_OPS (get_interest_name_suffix, type, h, suffix);
}

int
ipv6_set_interest_name_suffix (hicn_type_t type, hicn_protocol_t * h,
			       const hicn_name_suffix_t * suffix)
{
  return CHILD_OPS (set_interest_name_suffix, type, h, suffix);
}

int
ipv6_reset_interest_for_hash (hicn_type_t type, hicn_protocol_t * h)
{
  /* Sets everything to 0 up to IP destination address */
  memset (&(h->ipv6), 0, 24);

  return CHILD_OPS (reset_interest_for_hash, type, h);
}

int
ipv6_get_data_locator (hicn_type_t type, const hicn_protocol_t * h,
		       ip46_address_t * ip_address)
{
  ip_address->ip6 = h->ipv6.daddr;
  return HICN_LIB_ERROR_NONE;
}

int
ipv6_set_data_locator (hicn_type_t type, hicn_protocol_t * h,
		       const ip46_address_t * ip_address)
{
  h->ipv6.daddr = ip_address->ip6;
  return HICN_LIB_ERROR_NONE;
}

int
ipv6_get_data_name (hicn_type_t type, const hicn_protocol_t * h,
		    hicn_name_t * name)
{
  name->ip6.prefix_as_ip6 = h->ipv6.saddr;
#ifndef HICN_VPP_PLUGIN
  name->type = HNT_CONTIGUOUS_V6;
  name->len = HICN_V6_NAME_LEN;
#endif /* HICN_VPP_PLUGIN */
  return CHILD_OPS (get_data_name_suffix, type, h, &(name->ip6.suffix));
}

int
ipv6_set_data_name (hicn_type_t type, hicn_protocol_t * h,
		    const hicn_name_t * name)
{
  h->ipv6.saddr = name->ip6.prefix_as_ip6;
  return CHILD_OPS (set_data_name_suffix, type, h, &(name->ip6.suffix));
}

int
ipv6_get_data_name_suffix (hicn_type_t type, const hicn_protocol_t * h,
			   hicn_name_suffix_t * suffix)
{
  return CHILD_OPS (get_data_name_suffix, type, h, suffix);
}

int
ipv6_set_data_name_suffix (hicn_type_t type, hicn_protocol_t * h,
			   const hicn_name_suffix_t * suffix)
{
  return CHILD_OPS (set_data_name_suffix, type, h, suffix);
}

int
ipv6_get_data_pathlabel (hicn_type_t type, const hicn_protocol_t * h,
			 u32 * pathlabel)
{
  return CHILD_OPS (get_data_pathlabel, type, h, pathlabel);
}

int
ipv6_set_data_pathlabel (hicn_type_t type, hicn_protocol_t * h,
			 const u32 pathlabel)
{
  return CHILD_OPS (set_data_pathlabel, type, h, pathlabel);
}

int
ipv6_update_data_pathlabel (hicn_type_t type, hicn_protocol_t * h,
			    const hicn_faceid_t face_id)
{
  return CHILD_OPS (update_data_pathlabel, type, h, face_id);
}

int
ipv6_reset_data_for_hash (hicn_type_t type, hicn_protocol_t * h)
{
  /* IP: Set everithing to 0 up to destination address */
  memset (&h->ipv6, 0, 8);
  /* Clears destination address */
  memset (&(h->ipv6.daddr), 0, 16);

  return CHILD_OPS (reset_data_for_hash, type, h);
}

int
ipv6_get_lifetime (hicn_type_t type, const hicn_protocol_t * h,
		   hicn_lifetime_t * lifetime)
{
  return CHILD_OPS (get_lifetime, type, h, lifetime);
}

int
ipv6_set_lifetime (hicn_type_t type, hicn_protocol_t * h,
		   const hicn_lifetime_t lifetime)
{
  return CHILD_OPS (set_lifetime, type, h, lifetime);
}

#if 0
int
ipv6_update_checksums (hicn_type_t type, hicn_protocol_t * h,
		       u16 partial_csum, size_t payload_length)
{
  /* Retrieve payload length if not specified */
  if (payload_length == 0)
    {
      int rc = ipv6_get_payload_length (type, h, &payload_length);
      if (rc < 0)
	return rc;
    }

  /* Ignore the payload if payload_length = ~0 */
  if (payload_length == ~0)
    {
      payload_length = 0;
    }

  /* Build pseudo-header */
  ipv6_pseudo_header_t psh;
  psh.ip_src = h->ipv6.saddr;
  psh.ip_dst = h->ipv6.daddr;
  /* Size is u32 and not u16, we cannot copy and need to care about endianness */
  psh.size = htonl (ntohs (h->ipv6.len));
  psh.zeros = 0;
  psh.zero = 0;
  psh.protocol = h->ipv6.nxt;

  /* Compute partial checksum based on pseudo-header */
  if (partial_csum != 0)
    {
      partial_csum = ~partial_csum;
    }
  partial_csum = csum (&psh, IPV6_PSHDRLEN, partial_csum);

  return CHILD_OPS (update_checksums, type, h, partial_csum, payload_length);
}

int
ipv6_verify_checksums (hicn_type_t type, hicn_protocol_t * h,
		       u16 partial_csum, size_t payload_length)
{
  /* Retrieve payload length if not specified */
  if (payload_length == 0)
    {
      int rc = ipv6_get_payload_length (type, h, &payload_length);
      if (rc < 0)
	return rc;
    }

  /* Build pseudo-header */
  ipv6_pseudo_header_t pseudo;
  pseudo.ip_src = h->ipv6.saddr;
  pseudo.ip_dst = h->ipv6.daddr;
  /* Size is u32 and not u16, we cannot copy and need to care about endianness */
  pseudo.size = htonl (ntohs (h->ipv6.len));
  pseudo.zeros = 0;
  pseudo.zero = 0;
  pseudo.protocol = h->ipv6.nxt;

  /* Compute partial checksum based on pseudo-header */
  partial_csum = csum (&pseudo, IPV6_PSHDRLEN, 0);

  return CHILD_OPS (verify_checksums, type, h, partial_csum, payload_length);
}
#endif

int
ipv6_rewrite_interest (hicn_type_t type, hicn_protocol_t * h,
		       const ip46_address_t * addr_new,
		       ip46_address_t * addr_old)
{
  // ASSERT(addr_old == NULL);
  addr_old->ip6 = h->ipv6.saddr;
  h->ipv6.saddr = addr_new->ip6;

  return CHILD_OPS (rewrite_interest, type, h, addr_new, addr_old);
}

int
ipv6_rewrite_data (hicn_type_t type, hicn_protocol_t * h,
		   const ip46_address_t * addr_new, ip46_address_t * addr_old,
		   const hicn_faceid_t face_id)
{
  // ASSERT(addr_old == NULL);
  addr_old->ip6 = h->ipv6.daddr;
  h->ipv6.daddr = addr_new->ip6;

  return CHILD_OPS (rewrite_data, type, h, addr_new, addr_old, face_id);
}

int
ipv6_get_length (hicn_type_t type, const hicn_protocol_t * h,
		 size_t * header_length)
{
  *header_length = IPV6_HDRLEN + ntohs (h->ipv6.len);
  return HICN_LIB_ERROR_NONE;
}

int
ipv6_get_current_header_length (hicn_type_t type, const hicn_protocol_t * h,
				size_t * header_length)
{
  *header_length = IPV6_HDRLEN;
  return HICN_LIB_ERROR_NONE;
}

int
ipv6_get_header_length (hicn_type_t type, const hicn_protocol_t * h,
			size_t * header_length)
{
  size_t child_header_length = 0;
  int rc = CHILD_OPS (get_header_length, type, h, &child_header_length);
  if (rc < 0)
    return rc;
  *header_length = IPV6_HDRLEN + child_header_length;
  return HICN_LIB_ERROR_NONE;
}

int
ipv6_get_payload_length (hicn_type_t type, const hicn_protocol_t * h,
			 size_t * payload_length)
{
  size_t child_header_length;
  int rc = CHILD_OPS (get_header_length, type, h, &child_header_length);
  if (rc < 0)
    return rc;
  *payload_length = ntohs (h->ipv6.len) - child_header_length;
  return HICN_LIB_ERROR_NONE;
}

int
ipv6_set_payload_length (hicn_type_t type, hicn_protocol_t * h,
			 size_t payload_length)
{
  size_t child_header_length;
  int rc = CHILD_OPS (get_header_length, type, h, &child_header_length);
  if (rc < 0)
    return rc;
  h->ipv6.len = htons ( (u_short) (payload_length + child_header_length));
  return HICN_LIB_ERROR_NONE;
}

int
ipv6_get_signature_size (hicn_type_t type, const hicn_protocol_t * h,
			 size_t * signature_size)
{
  return CHILD_OPS (get_signature_size, type, h, signature_size);
}

int
ipv6_set_signature_size (hicn_type_t type, hicn_protocol_t * h,
			 size_t signature_size)
{
  return CHILD_OPS (set_signature_size, type, h, signature_size);
}

int
ipv6_set_signature_timestamp(hicn_type_t type, hicn_protocol_t * h,
       uint64_t signature_timestamp)
{
  return CHILD_OPS (set_signature_timestamp, type, h, signature_timestamp);
}

int
ipv6_get_signature_timestamp (hicn_type_t type, const hicn_protocol_t * h,
       uint64_t * signature_timestamp)
{
  return CHILD_OPS (get_signature_timestamp, type, h, signature_timestamp);
}

int
ipv6_set_validation_algorithm (hicn_type_t type, hicn_protocol_t * h,
       uint8_t validation_algorithm)
{
  return CHILD_OPS (set_validation_algorithm, type, h, validation_algorithm);
}

int
ipv6_get_validation_algorithm (hicn_type_t type, const hicn_protocol_t * h,
       uint8_t * validation_algorithm)
{
  return CHILD_OPS (get_validation_algorithm, type, h, validation_algorithm);
}

int
ipv6_set_key_id (hicn_type_t type, hicn_protocol_t * h,
       uint8_t *key_id)
{
  return CHILD_OPS (set_key_id, type, h, key_id);
}

int
ipv6_get_key_id (hicn_type_t type, hicn_protocol_t * h,
       uint8_t **key_id, uint8_t *key_id_size)
{
  return CHILD_OPS (get_key_id, type, h, key_id, key_id_size);
}

int
ipv6_get_signature (hicn_type_t type, hicn_protocol_t * h,
		              uint8_t ** signature)
{
  return CHILD_OPS (get_signature, type, h, signature);
}

DECLARE_HICN_OPS (ipv6);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
