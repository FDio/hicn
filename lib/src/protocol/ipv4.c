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
 * @file protocol/ipv4->c
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
#include <hicn/common.h>

#include "../ops.h"
#include "ipv4.h"

#define UINT16_T_MASK 0x0000ffff // 1111 1111 1111 1111

#define ipv4_get_payload_len(pkbuf, ipv4) htons (ipv4->len - pkbuf->payload)

int
ipv4_init_packet_header (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  assert (pkbuf->len == 0);
  if (IPV4_HDRLEN > pkbuf->buffer_size - pkbuf->len)
    return -1;
  pkbuf->len += IPV4_HDRLEN;

  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  hicn_packet_format_t format = hicn_packet_get_format (pkbuf);

  size_t header_len;
  hicn_packet_get_header_length_from_format (pkbuf->format, &header_len);

  /* We initialize the len considering an empty payload */
  *ipv4 = (_ipv4_header_t){
    .version_ihl = (IPV4_DEFAULT_VERSION << 4) | (0x0f & IPV4_DEFAULT_IHL),
    .tos = IPV4_DEFAULT_TOS,
    .len = htons (header_len),
    .id = htons (IPV4_DEFAULT_ID),
    .frag_off = htons (IPV4_DEFAULT_FRAG_OFF),
    .ttl = HICN_DEFAULT_TTL,
    .protocol = format.as_u8[pos + 1],
    .csum = 0,
    .saddr.as_u32 = 0,
    .daddr.as_u32 = 0,
  };

  return CALL_CHILD (init_packet_header, pkbuf, pos);
}

int
ipv4_get_interest_locator (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   hicn_ip_address_t *ip_address)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  ip_address->v4 = ipv4->saddr;
  return HICN_LIB_ERROR_NONE;
}

int
ipv4_set_interest_locator (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   const hicn_ip_address_t *ip_address)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  ipv4->saddr = ip_address->v4;
  return HICN_LIB_ERROR_NONE;
}

int
ipv4_get_interest_name (const hicn_packet_buffer_t *pkbuf, size_t pos,
			hicn_name_t *name)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  name->prefix.v4 = ipv4->daddr;
  return CALL_CHILD (get_interest_name_suffix, pkbuf, pos, &(name->suffix));
}

int
ipv4_set_interest_name (const hicn_packet_buffer_t *pkbuf, size_t pos,
			const hicn_name_t *name)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  ipv4->daddr = name->prefix.v4;
  return CALL_CHILD (set_interest_name_suffix, pkbuf, pos, &(name->suffix));
}

int
ipv4_get_interest_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			       hicn_name_suffix_t *suffix)
{
  return CALL_CHILD (get_interest_name_suffix, pkbuf, pos, suffix);
}

int
ipv4_set_interest_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			       const hicn_name_suffix_t *suffix)
{
  return CALL_CHILD (set_interest_name_suffix, pkbuf, pos, suffix);
}

int
ipv4_get_type (const hicn_packet_buffer_t *pkbuf, const size_t pos,
	       hicn_packet_type_t *type)
{
  return CALL_CHILD (get_type, pkbuf, pos, type);
}

int
ipv4_set_type (const hicn_packet_buffer_t *pkbuf, size_t pos,
	       hicn_packet_type_t type)
{
  return CALL_CHILD (set_type, pkbuf, pos, type);
}

int
ipv4_reset_interest_for_hash (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  /* Sets everything to 0 up to IP destination address */
  memset (ipv4, 0, 16);

  return CALL_CHILD (reset_interest_for_hash, pkbuf, pos);
}

int
ipv4_get_data_locator (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       hicn_ip_address_t *ip_address)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  ip_address->v4 = ipv4->daddr;
  return HICN_LIB_ERROR_NONE;
}

int
ipv4_set_data_locator (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       const hicn_ip_address_t *ip_address)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  ipv4->daddr = ip_address->v4;
  return HICN_LIB_ERROR_NONE;
}

int
ipv4_get_data_name (const hicn_packet_buffer_t *pkbuf, size_t pos,
		    hicn_name_t *name)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  name->prefix.v4 = ipv4->saddr;
  return CALL_CHILD (get_data_name_suffix, pkbuf, pos, &(name->suffix));
}

int
ipv4_set_data_name (const hicn_packet_buffer_t *pkbuf, size_t pos,
		    const hicn_name_t *name)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  ipv4->saddr = name->prefix.v4;
  return CALL_CHILD (set_data_name_suffix, pkbuf, pos, &(name->suffix));
}

int
ipv4_get_data_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   hicn_name_suffix_t *suffix)
{
  return CALL_CHILD (get_data_name_suffix, pkbuf, pos, suffix);
}

int
ipv4_set_data_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   const hicn_name_suffix_t *suffix)
{
  return CALL_CHILD (set_data_name_suffix, pkbuf, pos, suffix);
}

int
ipv4_get_data_path_label (const hicn_packet_buffer_t *pkbuf, size_t pos,
			  hicn_path_label_t *path_label)
{
  return CALL_CHILD (get_data_path_label, pkbuf, pos, path_label);
}

int
ipv4_set_data_path_label (const hicn_packet_buffer_t *pkbuf, size_t pos,
			  hicn_path_label_t path_label)
{
  return CALL_CHILD (set_data_path_label, pkbuf, pos, path_label);
}

int
ipv4_update_data_path_label (const hicn_packet_buffer_t *pkbuf, size_t pos,
			     const hicn_faceid_t face_id)
{
  return CALL_CHILD (update_data_path_label, pkbuf, pos, face_id);
}

int
ipv4_reset_data_for_hash (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  /* Sets everything to 0 up to source address */
  memset (ipv4, 0, 12);
  /* Clears destination address */
  memset (&(ipv4->daddr), 0, 4);

  return CALL_CHILD (reset_data_for_hash, pkbuf, pos);
}

int
ipv4_get_lifetime (const hicn_packet_buffer_t *pkbuf, size_t pos,
		   hicn_lifetime_t *lifetime)
{
  return CALL_CHILD (get_lifetime, pkbuf, pos, lifetime);
}

int
ipv4_set_lifetime (const hicn_packet_buffer_t *pkbuf, size_t pos,
		   const hicn_lifetime_t lifetime)
{
  return CALL_CHILD (set_lifetime, pkbuf, pos, lifetime);
}

int
ipv4_update_checksums (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       u16 partial_csum, size_t payload_len)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  /*
   * Checksum field is not accounted for in lower layers, so we can compute
   * them in any order. Note that it is only a header checksum.
   */
  ipv4->csum = 0;
  ipv4->csum = csum (pkbuf_get_header (pkbuf), IPV4_HDRLEN, 0);

  /* Retrieve payload len if not specified, as it is not available later */
  if (payload_len == 0)
    {
      payload_len = ipv4_get_payload_len (pkbuf, ipv4);
    }

  /* Ignore the payload if payload_len = ~0 */
  if (payload_len == ~0)
    {
      payload_len = 0;
    }

  /* Build pseudo-header */
  ipv4_pseudo_header_t psh;
  psh.ip_src = ipv4->saddr;
  psh.ip_dst = ipv4->daddr;
  /* Size is u32 and not u16, we cannot copy and need to care about endianness
   */
  psh.size = htons (ntohs (ipv4->len) - (u16) IPV4_HDRLEN);
  psh.zero = 0;
  psh.protocol = (u8) ipv4->protocol;

  /* Compute partial checksum based on pseudo-header */
  if (partial_csum != 0)
    {
      partial_csum = ~partial_csum;
    }
  partial_csum = csum (&psh, IPV4_PSHDRLEN, partial_csum);

  return CALL_CHILD (update_checksums, pkbuf, pos, partial_csum, payload_len);
}

int
ipv4_update_checksums_incremental (const hicn_packet_buffer_t *pkbuf,
				   size_t pos, u16 *old_val, u16 *new_val,
				   u8 size, bool skip_first)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  /* We update the child first */
  int rc = CALL_CHILD (update_checksums_incremental, pkbuf, pos, old_val,
		       new_val, size, false);
  if (rc < 0)
    return rc;

  if (!skip_first)
    {
      for (uint8_t i = 0; i < size; i++)
	{
	  uint16_t old_csum = ~ipv4->csum;
	  uint16_t not_old_val = ~(*old_val);
	  uint32_t sum = (uint32_t) old_csum + not_old_val + *new_val;

	  while (sum >> 16)
	    {
	      sum = (sum >> 16) + (sum & UINT16_T_MASK);
	    }

	  ipv4->csum = ~sum;
	  ++old_val;
	  ++new_val;
	}
    }

  return HICN_LIB_ERROR_NONE;
}

int
ipv4_verify_checksums (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       u16 partial_csum, size_t payload_len)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  /*
   * Checksum field is not accounted for in lower layers, so we can compute
   * them in any order. Note that it is only a header checksum.
   */
  if (csum (pkbuf_get_header (pkbuf), IPV4_HDRLEN, 0) != 0)
    return HICN_LIB_ERROR_CORRUPTED_PACKET;

  /* Retrieve payload len if not specified, as it is not available later */
  if (payload_len == 0)
    {
      payload_len = ipv4_get_payload_len (pkbuf, ipv4);
    }

  /* Build pseudo-header */
  ipv4_pseudo_header_t psh;
  psh.ip_src = ipv4->saddr;
  psh.ip_dst = ipv4->daddr;
  /* Size is u32 and not u16, we cannot copy and need to care about endianness
   */
  psh.size = htons (ntohs (ipv4->len) - (u16) IPV4_HDRLEN);
  psh.zero = 0;
  psh.protocol = (u8) ipv4->protocol;

  /* Compute partial checksum based on pseudo-header */
  partial_csum = csum (&psh, IPV4_PSHDRLEN, 0);

  return CALL_CHILD (verify_checksums, pkbuf, pos, partial_csum, payload_len);
}

int
ipv4_rewrite_interest (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       const hicn_ip_address_t *addr_new,
		       hicn_ip_address_t *addr_old)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  // ASSERT(addr_old == NULL);
  addr_old->v4 = ipv4->saddr;
  addr_old->pad[0] = 0;
  addr_old->pad[1] = 0;
  addr_old->pad[2] = 0;

  ipv4->saddr = addr_new->v4;
  ipv4->csum = 0;
  ipv4->csum = csum (&ipv4, IPV4_HDRLEN, 0);

  return CALL_CHILD (rewrite_interest, pkbuf, pos, addr_new, addr_old);
}

int
ipv4_rewrite_data (const hicn_packet_buffer_t *pkbuf, size_t pos,
		   const hicn_ip_address_t *addr_new,
		   hicn_ip_address_t *addr_old, const hicn_faceid_t face_id,
		   u8 reset_pl)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  // ASSERT(addr_old == NULL);
  addr_old->v4 = ipv4->daddr;
  addr_old->pad[0] = 0;
  addr_old->pad[1] = 0;
  addr_old->pad[2] = 0;

  ipv4->daddr = addr_new->v4;
  ipv4->csum = 0;
  ipv4->csum = csum (&ipv4, IPV4_HDRLEN, 0);

  return CALL_CHILD (rewrite_data, pkbuf, pos, addr_new, addr_old, face_id,
		     reset_pl);
}

int
ipv4_set_payload_len (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      size_t payload_len)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  size_t child_header_len = hicn_ops_vft[pos + 1]->header_len;

  ipv4->len = htons ((u16) (payload_len + IPV4_HDRLEN + child_header_len));
  return HICN_LIB_ERROR_NONE;
}

int
ipv4_get_payload_type (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       hicn_payload_type_t *payload_type)
{
  return CALL_CHILD (get_payload_type, pkbuf, pos, payload_type);
}

int
ipv4_set_payload_type (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       hicn_payload_type_t payload_type)
{
  return CALL_CHILD (set_payload_type, pkbuf, pos, payload_type);
}

int
ipv4_get_signature_size (const hicn_packet_buffer_t *pkbuf, size_t pos,
			 size_t *signature_size)
{
  return CALL_CHILD (get_signature_size, pkbuf, pos, signature_size);
}

int
ipv4_set_signature_size (const hicn_packet_buffer_t *pkbuf, size_t pos,
			 size_t signature_size)
{
  return CALL_CHILD (set_signature_size, pkbuf, pos, signature_size);
}

int
ipv4_set_signature_padding (const hicn_packet_buffer_t *pkbuf, size_t pos,
			    size_t padding)
{
  return CALL_CHILD (set_signature_padding, pkbuf, pos, padding);
}

int
ipv4_get_signature_padding (const hicn_packet_buffer_t *pkbuf, size_t pos,
			    size_t *padding)
{
  return CALL_CHILD (get_signature_padding, pkbuf, pos, padding);
}

int
ipv4_set_signature_timestamp (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      uint64_t signature_timestamp)
{
  return CALL_CHILD (set_signature_timestamp, pkbuf, pos, signature_timestamp);
}

int
ipv4_get_signature_timestamp (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      uint64_t *signature_timestamp)
{
  return CALL_CHILD (get_signature_timestamp, pkbuf, pos, signature_timestamp);
}

int
ipv4_set_validation_algorithm (const hicn_packet_buffer_t *pkbuf, size_t pos,
			       uint8_t validation_algorithm)
{
  return CALL_CHILD (set_validation_algorithm, pkbuf, pos,
		     validation_algorithm);
}

int
ipv4_get_validation_algorithm (const hicn_packet_buffer_t *pkbuf, size_t pos,
			       uint8_t *validation_algorithm)
{
  return CALL_CHILD (get_validation_algorithm, pkbuf, pos,
		     validation_algorithm);
}

int
ipv4_set_key_id (const hicn_packet_buffer_t *pkbuf, size_t pos,
		 uint8_t *key_id, size_t key_len)
{
  return CALL_CHILD (set_key_id, pkbuf, pos, key_id, key_len);
}

int
ipv4_get_key_id (const hicn_packet_buffer_t *pkbuf, size_t pos,
		 uint8_t **key_id, uint8_t *key_id_size)
{
  return CALL_CHILD (get_key_id, pkbuf, pos, key_id, key_id_size);
}

int
ipv4_get_signature (const hicn_packet_buffer_t *pkbuf, size_t pos,
		    uint8_t **signature)
{
  return CALL_CHILD (get_signature, pkbuf, pos, signature);
}

int
ipv4_has_signature (const hicn_packet_buffer_t *pkbuf, size_t pos, bool *flag)
{
  return CALL_CHILD (has_signature, pkbuf, pos, flag);
}

int
ipv4_is_last_data (const hicn_packet_buffer_t *pkbuf, size_t pos, int *is_last)
{
  return CALL_CHILD (is_last_data, pkbuf, pos, is_last);
}

int
ipv4_set_last_data (const hicn_packet_buffer_t *pkbuf, size_t pos)
{
  return CALL_CHILD (set_last_data, pkbuf, pos);
}

int
ipv4_get_ttl (const hicn_packet_buffer_t *pkbuf, size_t pos, u8 *hops)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  *hops = ipv4->ttl;

  return HICN_LIB_ERROR_NONE;
}

int
ipv4_set_ttl (const hicn_packet_buffer_t *pkbuf, size_t pos, u8 hops)
{
  _ipv4_header_t *ipv4 = pkbuf_get_ipv4 (pkbuf);

  ipv4->ttl = hops;

  return HICN_LIB_ERROR_NONE;
}

int
ipv4_get_src_port (const hicn_packet_buffer_t *pkbuf, size_t pos, u16 *port)
{
  return CALL_CHILD (get_src_port, pkbuf, pos, port);
}

int
ipv4_set_src_port (const hicn_packet_buffer_t *pkbuf, size_t pos, u16 port)
{
  return CALL_CHILD (set_src_port, pkbuf, pos, port);
}

int
ipv4_get_dst_port (const hicn_packet_buffer_t *pkbuf, size_t pos, u16 *port)
{
  return CALL_CHILD (get_dst_port, pkbuf, pos, port);
}

int
ipv4_set_dst_port (const hicn_packet_buffer_t *pkbuf, size_t pos, u16 port)
{
  return CALL_CHILD (set_dst_port, pkbuf, pos, port);
}

DECLARE_HICN_OPS (ipv4, IPV4_HDRLEN);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
