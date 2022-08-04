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

#include <stdlib.h>
#include <string.h>
#include <hicn/common.h>
#include <hicn/error.h>

#include "ipv6.h"
#include "../ops.h"

typedef unsigned short u_short;

#ifdef OPAQUE_IP
#define GET_IPV6_HEADER(pkbuf)                                                \
  (_ipv6_header_t *) ((pkbuf)->header + (pkbuf)->ipv6)
#else
#define GET_IPV6_HEADER(pkbuf) (_ipv6_header_t *) ((pkbuf)->header)
#endif /* OPAQUE_IP */

int
ipv6_init_packet_header (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  assert (pkbuf->len == 0);
  if (IPV6_HDRLEN > pkbuf->buffer_size - pkbuf->len)
    return -1;
  pkbuf->len += IPV6_HDRLEN;

  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  hicn_packet_format_t format = hicn_packet_get_format (pkbuf);

  size_t header_len;
  hicn_packet_get_header_length_from_format (pkbuf->format, &header_len);

  /* clang-format off */
  *ipv6 = (_ipv6_header_t){
    .saddr = IP6_ADDRESS_EMPTY,
    .daddr = IP6_ADDRESS_EMPTY,
    .version_class_flow = htonl ((IPV6_DEFAULT_VERSION << 28) |
				 (IPV6_DEFAULT_TRAFFIC_CLASS << 20) |
				 (IPV6_DEFAULT_FLOW_LABEL & 0xfffff)),
    .len = htons(header_len - IPV6_HDRLEN),
    .nxt = format.as_u8[pos + 1],
    .hlim = HICN_DEFAULT_TTL,
  };
  /* clang-format on */
  return CALL_CHILD (init_packet_header, pkbuf, pos);
}

int
ipv6_get_interest_locator (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   hicn_ip_address_t *ip_address)
{
  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  ip_address->v6 = ipv6->saddr;
  return HICN_LIB_ERROR_NONE;
}

int
ipv6_set_interest_locator (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   const hicn_ip_address_t *ip_address)
{
  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  ipv6->saddr = ip_address->v6;
  return HICN_LIB_ERROR_NONE;
}

int
ipv6_get_interest_name (const hicn_packet_buffer_t *pkbuf, size_t pos,
			hicn_name_t *name)
{
  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  name->prefix.v6 = ipv6->daddr;
  return CALL_CHILD (get_interest_name_suffix, pkbuf, pos, &(name->suffix));
}

int
ipv6_set_interest_name (const hicn_packet_buffer_t *pkbuf, size_t pos,
			const hicn_name_t *name)
{
  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  ipv6->daddr = name->prefix.v6;
  return CALL_CHILD (set_interest_name_suffix, pkbuf, pos, &(name->suffix));
}

int
ipv6_get_interest_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			       hicn_name_suffix_t *suffix)
{
  return CALL_CHILD (get_interest_name_suffix, pkbuf, pos, suffix);
}

int
ipv6_set_interest_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			       const hicn_name_suffix_t *suffix)
{
  return CALL_CHILD (set_interest_name_suffix, pkbuf, pos, suffix);
}

int
ipv6_get_type (const hicn_packet_buffer_t *pkbuf, const size_t pos,
	       hicn_packet_type_t *type)
{
  return CALL_CHILD (get_type, pkbuf, pos, type);
}

int
ipv6_set_type (const hicn_packet_buffer_t *pkbuf, size_t pos,
	       hicn_packet_type_t type)
{
  return CALL_CHILD (set_type, pkbuf, pos, type);
}

int
ipv6_reset_interest_for_hash (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  /* Sets everything to 0 up to IP destination address */
  memset (ipv6, 0, 24);

  return CALL_CHILD (reset_interest_for_hash, pkbuf, pos);
}

int
ipv6_get_data_locator (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       hicn_ip_address_t *ip_address)
{
  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  ip_address->v6 = ipv6->daddr;
  return HICN_LIB_ERROR_NONE;
}

int
ipv6_set_data_locator (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       const hicn_ip_address_t *ip_address)
{
  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  ipv6->daddr = ip_address->v6;
  return HICN_LIB_ERROR_NONE;
}

int
ipv6_get_data_name (const hicn_packet_buffer_t *pkbuf, size_t pos,
		    hicn_name_t *name)
{
  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  name->prefix.v6 = ipv6->saddr;
  return CALL_CHILD (get_data_name_suffix, pkbuf, pos, &(name->suffix));
}

int
ipv6_set_data_name (const hicn_packet_buffer_t *pkbuf, size_t pos,
		    const hicn_name_t *name)
{
  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  ipv6->saddr = name->prefix.v6;
  return CALL_CHILD (set_data_name_suffix, pkbuf, pos, &(name->suffix));
}

int
ipv6_get_data_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   hicn_name_suffix_t *suffix)
{
  return CALL_CHILD (get_data_name_suffix, pkbuf, pos, suffix);
}

int
ipv6_set_data_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   const hicn_name_suffix_t *suffix)
{
  return CALL_CHILD (set_data_name_suffix, pkbuf, pos, suffix);
}

int
ipv6_get_data_path_label (const hicn_packet_buffer_t *pkbuf, size_t pos,
			  hicn_path_label_t *path_label)
{
  return CALL_CHILD (get_data_path_label, pkbuf, pos, path_label);
}

int
ipv6_set_data_path_label (const hicn_packet_buffer_t *pkbuf, size_t pos,
			  hicn_path_label_t path_label)
{
  return CALL_CHILD (set_data_path_label, pkbuf, pos, path_label);
}

int
ipv6_update_data_path_label (const hicn_packet_buffer_t *pkbuf, size_t pos,
			     const hicn_faceid_t face_id)
{
  return CALL_CHILD (update_data_path_label, pkbuf, pos, face_id);
}

int
ipv6_reset_data_for_hash (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  /* IP: Set everithing to 0 up to destination address */
  memset (ipv6, 0, 8);
  /* Clears destination address */
  memset (&(ipv6->daddr), 0, 16);

  return CALL_CHILD (reset_data_for_hash, pkbuf, pos);
}

int
ipv6_get_lifetime (const hicn_packet_buffer_t *pkbuf, size_t pos,
		   hicn_lifetime_t *lifetime)
{
  return CALL_CHILD (get_lifetime, pkbuf, pos, lifetime);
}

int
ipv6_set_lifetime (const hicn_packet_buffer_t *pkbuf, size_t pos,
		   const hicn_lifetime_t lifetime)
{
  return CALL_CHILD (set_lifetime, pkbuf, pos, lifetime);
}

int
ipv6_update_checksums (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       u16 partial_csum, size_t payload_len)
{
  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  /* Retrieve payload len if not specified */
  if (payload_len == ~0)
    {
      payload_len = hicn_packet_get_len (pkbuf) - pkbuf->payload;
    }

  /* Build pseudo-header */
  ipv6_pseudo_header_t psh;
  psh.ip_src = ipv6->saddr;
  psh.ip_dst = ipv6->daddr;
  /* Size is u32 and not u16, we cannot copy and need to care about endianness
   */
  psh.size = htonl (ntohs (ipv6->len));
  psh.zeros = 0;
  psh.zero = 0;
  psh.protocol = ipv6->nxt;

  /* Compute partial checksum based on pseudo-header */
  if (partial_csum != 0)
    {
      partial_csum = ~partial_csum;
    }
  partial_csum = csum (&psh, IPV6_PSHDRLEN, partial_csum);

  return CALL_CHILD (update_checksums, pkbuf, pos, partial_csum, payload_len);
}

int
ipv6_update_checksums_incremental (const hicn_packet_buffer_t *pkbuf,
				   size_t pos, u16 *old_val, u16 *new_val,
				   u8 size, bool skip_first)
{
  /* We update the child only */
  return CALL_CHILD (update_checksums_incremental, pkbuf, pos, old_val,
		     new_val, size, false);
}

int
ipv6_verify_checksums (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       u16 partial_csum, size_t payload_len)
{
  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  /* Retrieve payload len if not specified */
  if (payload_len == ~0)
    {
      payload_len = hicn_packet_get_len (pkbuf) - pkbuf->payload;
    }

  /* Build pseudo-header */
  ipv6_pseudo_header_t pseudo;
  pseudo.ip_src = ipv6->saddr;
  pseudo.ip_dst = ipv6->daddr;
  /* Size is u32 and not u16, we cannot copy and need to care about endianness
   */
  pseudo.size = htonl (ntohs (ipv6->len));
  pseudo.zeros = 0;
  pseudo.zero = 0;
  pseudo.protocol = ipv6->nxt;

  /* Compute partial checksum based on pseudo-header */
  if (partial_csum != 0)
    {
      partial_csum = ~partial_csum;
    }
  partial_csum = csum (&pseudo, IPV6_PSHDRLEN, partial_csum);

  return CALL_CHILD (verify_checksums, pkbuf, pos, partial_csum, payload_len);
}

int
ipv6_rewrite_interest (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       const hicn_ip_address_t *addr_new,
		       hicn_ip_address_t *addr_old)
{
  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  // ASSERT(addr_old == NULL);
  addr_old->v6 = ipv6->saddr;
  ipv6->saddr = addr_new->v6;

  return CALL_CHILD (rewrite_interest, pkbuf, pos, addr_new, addr_old);
}

int
ipv6_rewrite_data (const hicn_packet_buffer_t *pkbuf, size_t pos,
		   const hicn_ip_address_t *addr_new,
		   hicn_ip_address_t *addr_old, const hicn_faceid_t face_id,
		   u8 reset_pl)
{
  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  // ASSERT(addr_old == NULL);
  addr_old->v6 = ipv6->daddr;
  ipv6->daddr = addr_new->v6;

  return CALL_CHILD (rewrite_data, pkbuf, pos, addr_new, addr_old, face_id,
		     reset_pl);
}

int
ipv6_set_payload_len (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      size_t payload_len)
{
  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  ipv6->len = htons ((u_short) (payload_len + pkbuf->payload - IPV6_HDRLEN));
  return HICN_LIB_ERROR_NONE;
}

int
ipv6_get_payload_type (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       hicn_payload_type_t *payload_type)
{
  return CALL_CHILD (get_payload_type, pkbuf, pos, payload_type);
}

int
ipv6_set_payload_type (const hicn_packet_buffer_t *pkbuf, size_t pos,
		       hicn_payload_type_t payload_type)
{
  return CALL_CHILD (set_payload_type, pkbuf, pos, payload_type);
}

int
ipv6_get_signature_size (const hicn_packet_buffer_t *pkbuf, size_t pos,
			 size_t *signature_size)
{
  return CALL_CHILD (get_signature_size, pkbuf, pos, signature_size);
}

int
ipv6_set_signature_size (const hicn_packet_buffer_t *pkbuf, size_t pos,
			 size_t signature_size)
{
  return CALL_CHILD (set_signature_size, pkbuf, pos, signature_size);
}

int
ipv6_set_signature_padding (const hicn_packet_buffer_t *pkbuf, size_t pos,
			    size_t padding)
{
  return CALL_CHILD (set_signature_padding, pkbuf, pos, padding);
}

int
ipv6_get_signature_padding (const hicn_packet_buffer_t *pkbuf, size_t pos,
			    size_t *padding)
{
  return CALL_CHILD (get_signature_padding, pkbuf, pos, padding);
}

int
ipv6_set_signature_timestamp (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      uint64_t signature_timestamp)
{
  return CALL_CHILD (set_signature_timestamp, pkbuf, pos, signature_timestamp);
}

int
ipv6_get_signature_timestamp (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      uint64_t *signature_timestamp)
{
  return CALL_CHILD (get_signature_timestamp, pkbuf, pos, signature_timestamp);
}

int
ipv6_set_validation_algorithm (const hicn_packet_buffer_t *pkbuf, size_t pos,
			       uint8_t validation_algorithm)
{
  return CALL_CHILD (set_validation_algorithm, pkbuf, pos,
		     validation_algorithm);
}

int
ipv6_get_validation_algorithm (const hicn_packet_buffer_t *pkbuf, size_t pos,
			       uint8_t *validation_algorithm)
{
  return CALL_CHILD (get_validation_algorithm, pkbuf, pos,
		     validation_algorithm);
}

int
ipv6_set_key_id (const hicn_packet_buffer_t *pkbuf, size_t pos,
		 uint8_t *key_id, size_t key_len)
{
  return CALL_CHILD (set_key_id, pkbuf, pos, key_id, key_len);
}

int
ipv6_get_key_id (const hicn_packet_buffer_t *pkbuf, size_t pos,
		 uint8_t **key_id, uint8_t *key_id_size)
{
  return CALL_CHILD (get_key_id, pkbuf, pos, key_id, key_id_size);
}

int
ipv6_get_signature (const hicn_packet_buffer_t *pkbuf, size_t pos,
		    uint8_t **signature)
{
  return CALL_CHILD (get_signature, pkbuf, pos, signature);
}

int
ipv6_has_signature (const hicn_packet_buffer_t *pkbuf, size_t pos, bool *flag)
{
  return CALL_CHILD (has_signature, pkbuf, pos, flag);
}

int
ipv6_is_last_data (const hicn_packet_buffer_t *pkbuf, size_t pos, int *is_last)
{
  return CALL_CHILD (is_last_data, pkbuf, pos, is_last);
}

int
ipv6_set_last_data (const hicn_packet_buffer_t *pkbuf, size_t pos)
{
  return CALL_CHILD (set_last_data, pkbuf, pos);
}

int
ipv6_get_ttl (const hicn_packet_buffer_t *pkbuf, size_t pos, u8 *hops)
{
  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  *hops = ipv6->hlim;

  return HICN_LIB_ERROR_NONE;
}

int
ipv6_set_ttl (const hicn_packet_buffer_t *pkbuf, size_t pos, u8 hops)
{

  _ipv6_header_t *ipv6 = pkbuf_get_ipv6 (pkbuf);

  ipv6->hlim = hops;

  return HICN_LIB_ERROR_NONE;
}

int
ipv6_get_src_port (const hicn_packet_buffer_t *pkbuf, size_t pos, u16 *port)
{
  return CALL_CHILD (get_src_port, pkbuf, pos, port);
}

int
ipv6_set_src_port (const hicn_packet_buffer_t *pkbuf, size_t pos, u16 port)
{
  return CALL_CHILD (set_src_port, pkbuf, pos, port);
}

int
ipv6_get_dst_port (const hicn_packet_buffer_t *pkbuf, size_t pos, u16 *port)
{
  return CALL_CHILD (get_dst_port, pkbuf, pos, port);
}

int
ipv6_set_dst_port (const hicn_packet_buffer_t *pkbuf, size_t pos, u16 port)
{
  return CALL_CHILD (set_dst_port, pkbuf, pos, port);
}

DECLARE_HICN_OPS (ipv6, IPV6_HDRLEN);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
