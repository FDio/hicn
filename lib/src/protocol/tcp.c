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

#include <string.h>

#include <hicn/base.h>
#include <hicn/error.h>

#include "tcp.h"
#include "../ops.h"

#define TCP_DEFAULT_SRC_PORT	    0x8000
#define TCP_DEFAULT_DST_PORT	    0x0080
#define TCP_DEFAULT_WINDOW_SIZE	    0 // In [2, 65535]
#define TCP_DEFAULT_HLEN	    20
#define TCP_DEFAULT_DATA_OFFSET_RES (TCP_DEFAULT_HLEN >> 2) << 4
#define TCP_DEFAULT_CWR		    0
#define TCP_DEFAULT_ECE		    0
#define TCP_DEFAULT_URG		    0
#define TCP_DEFAULT_ACK		    0
#define TCP_DEFAULT_PSH		    0
#define TCP_DEFAULT_RST		    0
#define TCP_DEFAULT_SYN		    1
#define TCP_DEFAULT_FIN		    0

#define UINT16_T_MASK 0x0000ffff // 1111 1111 1111 1111

DECLARE_get_interest_locator (tcp, UNEXPECTED);
DECLARE_set_interest_locator (tcp, UNEXPECTED);
DECLARE_get_interest_name (tcp, UNEXPECTED);
DECLARE_set_interest_name (tcp, UNEXPECTED);
DECLARE_get_data_locator (tcp, UNEXPECTED);
DECLARE_set_data_locator (tcp, UNEXPECTED);
DECLARE_get_data_name (tcp, UNEXPECTED);
DECLARE_set_data_name (tcp, UNEXPECTED);
DECLARE_set_payload_len (tcp, UNEXPECTED);
DECLARE_get_ttl (tcp, UNEXPECTED);
DECLARE_set_ttl (tcp, UNEXPECTED);

int tcp_update_checksums_incremental (const hicn_packet_buffer_t *pkbuf,
				      size_t pos, u16 *old_val, u16 *new_val,
				      u8 size, bool skip_first);

static inline void
reset_for_hash (hicn_packet_buffer_t *pkbuf)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  tcp->sport = 0;
  tcp->dport = 0;
  tcp->seq_ack = 0;
  tcp->data_offset_and_reserved = 0;
  tcp->flags = 0;
  tcp->window = 0;
  tcp->csum = 0;
  tcp->urg_ptr = 0;
}

static inline int
check_tcp_checksum (u16 csum)
{
  /* As per RFC1624
   * In one's complement, there are two representations of zero: the all
   * zero and the all one bit values, often referred to as +0 and -0.
   * One's complement addition of non-zero inputs can produce -0 as a
   * result, but never +0.  Since there is guaranteed to be at least one
   * non-zero field in the IP header, and the checksum field in the
   * protocol header is the complement of the sum, the checksum field can
   * never contain ~(+0), which is -0 (0xFFFF).  It can, however, contain
   * ~(-0), which is +0 (0x0000).
   */
  if (csum == 0xffff)
    {
      /* Invalid checksum, no need to compute incremental update */
      return HICN_LIB_ERROR_REWRITE_CKSUM_REQUIRED;
    }

  return HICN_LIB_ERROR_NONE;
}

int
tcp_init_packet_header (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  pkbuf->tcp = pkbuf->len;
  if (TCP_HDRLEN > pkbuf->buffer_size - pkbuf->len)
    return -1;
  pkbuf->len += TCP_HDRLEN;

  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  hicn_packet_format_t format = hicn_packet_get_format (pkbuf);

  *tcp = (_tcp_header_t){
    .sport = htons (TCP_DEFAULT_SRC_PORT),
    .dport = htons (TCP_DEFAULT_DST_PORT),
    .seq = 0,
    .seq_ack = 0,
    .data_offset_and_reserved = TCP_DEFAULT_DATA_OFFSET_RES,
    .flags = TCP_DEFAULT_CWR << 7 | TCP_DEFAULT_ECE << 6 |
	     TCP_DEFAULT_URG << 5 | TCP_DEFAULT_ACK << 4 |
	     TCP_DEFAULT_PSH << 3 | TCP_DEFAULT_RST << 2 |
	     TCP_DEFAULT_SYN << 1 | TCP_DEFAULT_FIN << 0,
    .window = htons (TCP_DEFAULT_WINDOW_SIZE),
    .csum = 0xffff,
    .urg_ptr = 65000,
  };

  uint8_t ah_flag = ((format.as_u8[pos + 1] == IPPROTO_AH) ? AH_FLAG : 0);

  tcp->flags |= ah_flag;

  return CALL_CHILD (init_packet_header, pkbuf, pos);
}

int
tcp_get_type (const hicn_packet_buffer_t *pkbuf, const size_t pos,
	      hicn_packet_type_t *type)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  /* Data packets have the ECE bit set */
  if (tcp->flags & HICN_TCP_FLAG_ECE)
    *type = HICN_PACKET_TYPE_DATA;
  else
    *type = HICN_PACKET_TYPE_INTEREST;
  return HICN_LIB_ERROR_NONE;
}

int
tcp_set_type (const hicn_packet_buffer_t *pkbuf, size_t pos,
	      hicn_packet_type_t type)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  switch (type)
    {
    case HICN_PACKET_TYPE_INTEREST:
      tcp->flags &= ~HICN_TCP_FLAG_ECE;
      break;
    case HICN_PACKET_TYPE_DATA:
      tcp->flags |= HICN_TCP_FLAG_ECE;
      break;
    default:
      return HICN_LIB_ERROR_INVALID_PARAMETER;
    }
  return HICN_LIB_ERROR_NONE;
}

int
tcp_get_interest_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      hicn_name_suffix_t *suffix)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  *suffix = ntohl (tcp->name_suffix);
  return HICN_LIB_ERROR_NONE;
}

int
tcp_set_interest_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      const hicn_name_suffix_t *suffix)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  int rc = tcp_set_type (pkbuf, pos, HICN_PACKET_TYPE_INTEREST);
  if (rc)
    return rc;

  tcp->name_suffix = htonl (*suffix);

  return HICN_LIB_ERROR_NONE;
}

int
tcp_reset_interest_for_hash (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  reset_for_hash (pkbuf);
  return CALL_CHILD (reset_interest_for_hash, pkbuf, pos);
}

int
tcp_get_data_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			  hicn_name_suffix_t *suffix)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  *suffix = ntohl (tcp->name_suffix);
  return HICN_LIB_ERROR_NONE;
}

int
tcp_set_data_name_suffix (const hicn_packet_buffer_t *pkbuf, size_t pos,
			  const hicn_name_suffix_t *suffix)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  int rc = tcp_set_type (pkbuf, pos, HICN_PACKET_TYPE_DATA);
  if (rc)
    return rc;

  tcp->name_suffix = htonl (*suffix);
  return HICN_LIB_ERROR_NONE;
}

int
tcp_get_data_path_label (const hicn_packet_buffer_t *pkbuf, size_t pos,
			 hicn_path_label_t *path_label)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  *path_label =
    (hicn_path_label_t) (tcp->seq_ack >> (32 - HICN_PATH_LABEL_SIZE_BITS));
  return HICN_LIB_ERROR_NONE;
}

int
tcp_set_data_path_label (const hicn_packet_buffer_t *pkbuf, size_t pos,
			 hicn_path_label_t path_label)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  hicn_path_label_t old_path_label;
  tcp_get_data_path_label (pkbuf, pos, &old_path_label);

  tcp->seq_ack = (path_label << (32 - HICN_PATH_LABEL_SIZE_BITS));

  tcp_update_checksums_incremental (
    pkbuf, pos, (uint16_t *) &old_path_label, (uint16_t *) &path_label,
    sizeof (hicn_path_label_t) / sizeof (uint16_t), true);

  return HICN_LIB_ERROR_NONE;
}

int
tcp_update_data_path_label (const hicn_packet_buffer_t *pkbuf, size_t pos,
			    const hicn_faceid_t face_id)
{
  assert (sizeof (hicn_path_label_t) == 1);

  hicn_path_label_t old_path_label;
  hicn_path_label_t new_path_label;

  tcp_get_data_path_label (pkbuf, pos, &old_path_label);
  update_path_label (old_path_label, face_id, &new_path_label);
  tcp_set_data_path_label (pkbuf, pos, new_path_label);

  return HICN_LIB_ERROR_NONE;
}

int
tcp_reset_data_for_hash (hicn_packet_buffer_t *pkbuf, size_t pos)
{
  reset_for_hash (pkbuf);
  return CALL_CHILD (reset_data_for_hash, pkbuf, pos);
}

int
tcp_get_lifetime (const hicn_packet_buffer_t *pkbuf, size_t pos,
		  hicn_lifetime_t *lifetime)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  *lifetime = ntohs (tcp->urg_ptr) << (tcp->data_offset_and_reserved & 0xF);
  return HICN_LIB_ERROR_NONE;
}

int
tcp_set_lifetime (const hicn_packet_buffer_t *pkbuf, size_t pos,
		  const hicn_lifetime_t lifetime)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  u8 multiplier = 0;
  u32 lifetime_scaled = lifetime;

  if (HICN_EXPECT_FALSE (lifetime >= HICN_MAX_LIFETIME))
    {
      tcp->urg_ptr = htons (HICN_MAX_LIFETIME_SCALED);
      tcp->data_offset_and_reserved =
	(tcp->data_offset_and_reserved & ~0x0F) | HICN_MAX_LIFETIME_MULTIPLIER;
      return HICN_LIB_ERROR_NONE;
    }

  while (lifetime_scaled > HICN_MAX_LIFETIME_SCALED &&
	 multiplier <= HICN_MAX_LIFETIME_MULTIPLIER)
    {
      multiplier++;
      lifetime_scaled = lifetime_scaled >> 1;
    }

  tcp->urg_ptr = htons (lifetime_scaled);
  tcp->data_offset_and_reserved =
    (tcp->data_offset_and_reserved & ~0x0F) | multiplier;

  return HICN_LIB_ERROR_NONE;
}

int
tcp_update_checksums (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      u16 partial_csum, size_t payload_len)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  /* TODO bound checks for payload_len based on pkbuf size */
  assert (payload_len != ~0);

  tcp->csum = 0;

  if (HICN_EXPECT_TRUE (partial_csum != 0))
    {
      partial_csum = ~partial_csum;
    }

  tcp->csum =
    csum (pkbuf_get_header (pkbuf), TCP_HDRLEN + payload_len, partial_csum);

  return CALL_CHILD (update_checksums, pkbuf, pos, 0, payload_len);
}

int
tcp_update_checksums_incremental (const hicn_packet_buffer_t *pkbuf,
				  size_t pos, u16 *old_val, u16 *new_val,
				  u8 size, bool skip_first)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  if (skip_first)
    return HICN_LIB_ERROR_INVALID_PARAMETER;

  for (uint8_t i = 0; i < size; i++)
    {
      uint16_t old_csum = ~tcp->csum;
      uint16_t not_old_val = ~(*old_val);
      uint32_t sum = (uint32_t) old_csum + not_old_val + *new_val;

      while (sum >> 16)
	{
	  sum = (sum >> 16) + (sum & UINT16_T_MASK);
	}

      tcp->csum = ~sum;
      ++old_val;
      ++new_val;
    }

  return CALL_CHILD (update_checksums_incremental, pkbuf, pos, old_val,
		     new_val, size, false);
}

int
tcp_verify_checksums (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      u16 partial_csum, size_t payload_len)
{
  if (HICN_EXPECT_TRUE (partial_csum != 0))
    {
      partial_csum = ~partial_csum;
    }

  if (csum (pkbuf_get_header (pkbuf), TCP_HDRLEN + payload_len,
	    partial_csum) != 0)
    return HICN_LIB_ERROR_CORRUPTED_PACKET;
  return CALL_CHILD (verify_checksums, pkbuf, pos, 0, payload_len);
}

#define TCP_OFFSET_MASK		       13
#define TCP_OFFSET_DATA_OFFSET	       12
#define TCP_OFFSET_IN_BITS_DATA_OFFSET 0
#define TCP_OFFSET_IN_BITS_RESERVED    4
#define TCP_OFFSET_IN_BITS_NS	       7

#define TCP_DEFAULT_SRC_PORT	0x8000
#define TCP_DEFAULT_DST_PORT	0x0080
#define TCP_DEFAULT_WINDOW_SIZE 0 // In [2, 65535]
#define TCP_DEFAULT_DATA_OFFSET                                               \
  5 // Size of the TCP header in words (= 4 bytes). Must be greater or equal
    // than 5.
#define TCP_DEFAULT_CWR 0
#define TCP_DEFAULT_ECE 0
#define TCP_DEFAULT_URG 0
#define TCP_DEFAULT_ACK 0
#define TCP_DEFAULT_PSH 0
#define TCP_DEFAULT_RST 0
#define TCP_DEFAULT_SYN 1
#define TCP_DEFAULT_FIN 0

int
tcp_rewrite_interest (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      const hicn_ip_address_t *addr_new,
		      hicn_ip_address_t *addr_old)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  _ipv6_header_t *ip6 = pkbuf_get_ipv6 (pkbuf);

  u16 *tcp_checksum = &(tcp->csum);
  int ret = check_tcp_checksum (*tcp_checksum);

  if (ret)
    {
      return ret;
    }

  /*
   * Padding fields are set to zero so we can apply checksum on the
   * whole struct by interpreting it as IPv6 in all cases
   *
   * v4 code would be:
   * csum = ip_csum_sub_even (*tcp_checksum, h->tcp.saddr.as_u32);
   * csum = ip_csum_add_even (csum, h->tcp.saddr.as_u32);
   */
  hicn_ip_csum_t csum =
    ip_csum_sub_even (*tcp_checksum, (hicn_ip_csum_t) (ip6->saddr.as_u64[0]));
  csum = ip_csum_sub_even (csum, (hicn_ip_csum_t) (ip6->saddr.as_u64[1]));
  csum = ip_csum_add_even (csum, (hicn_ip_csum_t) (ip6->saddr.as_u64[0]));
  csum = ip_csum_add_even (csum, (hicn_ip_csum_t) (ip6->saddr.as_u64[1]));

  *tcp_checksum = ip_csum_fold (csum);

  return HICN_LIB_ERROR_NONE;
}

int
tcp_rewrite_data (const hicn_packet_buffer_t *pkbuf, size_t pos,
		  const hicn_ip_address_t *addr_new,
		  hicn_ip_address_t *addr_old, const hicn_faceid_t face_id,
		  u8 reset_pl)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  u16 *tcp_checksum = &(tcp->csum);
  int ret = check_tcp_checksum (*tcp_checksum);

  /*
   * update path label
   */
  u16 old_pl = tcp->seq_ack;
  if (reset_pl)
    tcp->seq_ack = 0;
  tcp_update_data_path_label (pkbuf, pos, face_id);

  if (ret)
    {
      return ret;
    }

  /*
   * Padding fields are set to zero so we can apply checksum on the
   * whole struct by interpreting it as IPv6 in all cases
   *
   * v4 code would be:
   * csum = ip_csum_sub_even (*tcp_checksum, h->tcp.saddr.as_u32);
   * csum = ip_csum_add_even (csum, h->tcp.saddr.as_u32);
   */
  hicn_ip_csum_t csum = ip_csum_sub_even (
    *tcp_checksum, (hicn_ip_csum_t) (addr_old->v6.as_u64[0]));
  csum = ip_csum_sub_even (*tcp_checksum,
			   (hicn_ip_csum_t) (addr_old->v6.as_u64[1]));
  csum = ip_csum_add_even (csum, (hicn_ip_csum_t) (addr_new->v6.as_u64[0]));
  csum = ip_csum_add_even (csum, (hicn_ip_csum_t) (addr_new->v6.as_u64[1]));

  csum = ip_csum_sub_even (csum, old_pl);
  csum = ip_csum_add_even (csum, tcp->seq_ack);

  *tcp_checksum = ip_csum_fold (csum);

  return HICN_LIB_ERROR_NONE;
}

int
tcp_get_signature_size (const hicn_packet_buffer_t *pkbuf, size_t pos,
			size_t *signature_size)
{
  return CALL_CHILD (get_signature_size, pkbuf, pos, signature_size);
}

int
tcp_set_signature_size (const hicn_packet_buffer_t *pkbuf, size_t pos,
			size_t signature_size)
{
  return CALL_CHILD (set_signature_size, pkbuf, pos, signature_size);
}

int
tcp_set_signature_padding (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   size_t padding)
{
  return CALL_CHILD (set_signature_padding, pkbuf, pos, padding);
}

int
tcp_get_signature_padding (const hicn_packet_buffer_t *pkbuf, size_t pos,
			   size_t *padding)
{
  return CALL_CHILD (get_signature_padding, pkbuf, pos, padding);
}

int
tcp_set_signature_timestamp (const hicn_packet_buffer_t *pkbuf, size_t pos,
			     uint64_t signature_timestamp)
{
  return CALL_CHILD (set_signature_timestamp, pkbuf, pos, signature_timestamp);
}

int
tcp_get_signature_timestamp (const hicn_packet_buffer_t *pkbuf, size_t pos,
			     uint64_t *signature_timestamp)
{
  return CALL_CHILD (get_signature_timestamp, pkbuf, pos, signature_timestamp);
}

int
tcp_set_validation_algorithm (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      uint8_t validation_algorithm)
{
  return CALL_CHILD (set_validation_algorithm, pkbuf, pos,
		     validation_algorithm);
}

int
tcp_get_validation_algorithm (const hicn_packet_buffer_t *pkbuf, size_t pos,
			      uint8_t *validation_algorithm)
{
  return CALL_CHILD (get_validation_algorithm, pkbuf, pos,
		     validation_algorithm);
}

int
tcp_set_key_id (const hicn_packet_buffer_t *pkbuf, size_t pos, uint8_t *key_id,
		size_t key_len)
{
  return CALL_CHILD (set_key_id, pkbuf, pos, key_id, key_len);
}

int
tcp_get_key_id (const hicn_packet_buffer_t *pkbuf, size_t pos,
		uint8_t **key_id, uint8_t *key_id_size)
{
  return CALL_CHILD (get_key_id, pkbuf, pos, key_id, key_id_size);
}

int
tcp_get_signature (const hicn_packet_buffer_t *pkbuf, size_t pos,
		   uint8_t **signature)
{
  return CALL_CHILD (get_signature, pkbuf, pos, signature);
}

int
tcp_has_signature (const hicn_packet_buffer_t *pkbuf, size_t pos, bool *flag)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  *flag = tcp->flags & AH_FLAG;
  return HICN_LIB_ERROR_NONE;
}

int
tcp_get_payload_type (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      hicn_payload_type_t *payload_type)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  *payload_type = ((tcp->flags & HICN_TCP_FLAG_URG) == HICN_TCP_FLAG_URG);
  return HICN_LIB_ERROR_NONE;
}

int
tcp_set_payload_type (const hicn_packet_buffer_t *pkbuf, size_t pos,
		      hicn_payload_type_t payload_type)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  if (payload_type != HPT_DATA && payload_type != HPT_MANIFEST)
    return HICN_LIB_ERROR_INVALID_PARAMETER;

  if (payload_type)
    tcp->flags |= HICN_TCP_FLAG_URG;
  else
    tcp->flags &= ~HICN_TCP_FLAG_URG;

  return HICN_LIB_ERROR_NONE;
}

int
tcp_is_last_data (const hicn_packet_buffer_t *pkbuf, size_t pos, int *is_last)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  *is_last = (tcp->flags & HICN_TCP_FLAG_RST) == HICN_TCP_FLAG_RST;
  return HICN_LIB_ERROR_NONE;
}

int
tcp_set_last_data (const hicn_packet_buffer_t *pkbuf, size_t pos)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  tcp->flags |= HICN_TCP_FLAG_RST;
  return HICN_LIB_ERROR_NONE;
}

int
tcp_get_src_port (const hicn_packet_buffer_t *pkbuf, size_t pos, u16 *port)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  *port = ntohs (tcp->sport);
  return HICN_LIB_ERROR_NONE;
}

int
tcp_set_src_port (const hicn_packet_buffer_t *pkbuf, size_t pos, u16 port)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  tcp->sport = htons (port);
  return HICN_LIB_ERROR_NONE;
}

int
tcp_get_dst_port (const hicn_packet_buffer_t *pkbuf, size_t pos, u16 *port)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  *port = ntohs (tcp->dport);
  return HICN_LIB_ERROR_NONE;
}

int
tcp_set_dst_port (const hicn_packet_buffer_t *pkbuf, size_t pos, u16 port)
{
  _tcp_header_t *tcp = pkbuf_get_tcp (pkbuf);
  tcp->dport = htons (port);
  return HICN_LIB_ERROR_NONE;
}

DECLARE_HICN_OPS (tcp, TCP_HDRLEN);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
