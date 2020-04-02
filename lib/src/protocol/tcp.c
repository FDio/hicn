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

#include <string.h>
#include <hicn/protocol/tcp.h>

#include <hicn/error.h>
#include <hicn/ops.h>

#define TCP_DEFAULT_SRC_PORT           0x8000
#define TCP_DEFAULT_DST_PORT           0x0080
#define TCP_DEFAULT_WINDOW_SIZE        0	// In [2, 65535]
#define TCP_DEFAULT_HLEN               20
#define TCP_DEFAULT_DATA_OFFSET_RES    (TCP_DEFAULT_HLEN >> 2) << 4
#define TCP_DEFAULT_CWR                0
#define TCP_DEFAULT_ECE                0
#define TCP_DEFAULT_URG                0
#define TCP_DEFAULT_ACK                0
#define TCP_DEFAULT_PSH                0
#define TCP_DEFAULT_RST                0
#define TCP_DEFAULT_SYN                1
#define TCP_DEFAULT_FIN                0

DECLARE_get_interest_locator (tcp, UNEXPECTED);
DECLARE_set_interest_locator (tcp, UNEXPECTED);
DECLARE_get_interest_name (tcp, UNEXPECTED);
DECLARE_set_interest_name (tcp, UNEXPECTED);
DECLARE_get_data_locator (tcp, UNEXPECTED);
DECLARE_set_data_locator (tcp, UNEXPECTED);
DECLARE_get_data_name (tcp, UNEXPECTED);
DECLARE_set_data_name (tcp, UNEXPECTED);
DECLARE_get_length (tcp, UNEXPECTED);
DECLARE_get_payload_length (tcp, UNEXPECTED);
DECLARE_set_payload_length (tcp, UNEXPECTED);

int
tcp_init_packet_header (hicn_type_t type, hicn_protocol_t * h)
{
  h->tcp = (_tcp_header_t)
  {
  .sport = htons (TCP_DEFAULT_SRC_PORT),.dport =
      htons (TCP_DEFAULT_DST_PORT),.seq = 0,.seq_ack =
      0,.data_offset_and_reserved = TCP_DEFAULT_DATA_OFFSET_RES,.flags =
      TCP_DEFAULT_CWR << 7 | TCP_DEFAULT_ECE << 6 | TCP_DEFAULT_URG << 5 |
      TCP_DEFAULT_ACK << 4 | TCP_DEFAULT_PSH << 3 | TCP_DEFAULT_RST << 2 |
      TCP_DEFAULT_SYN << 1 | TCP_DEFAULT_FIN << 0,.window =
      htons (TCP_DEFAULT_WINDOW_SIZE),.csum = 0,.urg_ptr = 65000,};

  uint8_t ah_flag = type.l2 == IPPROTO_AH ? AH_FLAG : 0;

  h->tcp.flags |= ah_flag;

  return CHILD_OPS (init_packet_header, type, h);
}

int
tcp_get_interest_name_suffix (hicn_type_t type, const hicn_protocol_t * h,
			      hicn_name_suffix_t * suffix)
{
  *suffix = ntohl (h->tcp.name_suffix);
  return HICN_LIB_ERROR_NONE;
}

int
tcp_set_interest_name_suffix (hicn_type_t type, hicn_protocol_t * h,
			      const hicn_name_suffix_t * suffix)
{
  h->tcp.name_suffix = htonl (*suffix);

  return HICN_LIB_ERROR_NONE;
}

int
tcp_reset_interest_for_hash (hicn_type_t type, hicn_protocol_t * h)
{
  memset (&(h->tcp), 0, 4);
  memset (&(h->tcp.seq_ack), 0, 12);

  return CHILD_OPS (reset_interest_for_hash, type, h);
}


int
tcp_get_data_name_suffix (hicn_type_t type, const hicn_protocol_t * h,
			  hicn_name_suffix_t * suffix)
{
  *suffix = ntohl (h->tcp.name_suffix);
  return HICN_LIB_ERROR_NONE;
}

int
tcp_set_data_name_suffix (hicn_type_t type, hicn_protocol_t * h,
			  const hicn_name_suffix_t * suffix)
{
  h->tcp.name_suffix = htonl (*suffix);
  return HICN_LIB_ERROR_NONE;
}

int
tcp_get_data_pathlabel (hicn_type_t type, const hicn_protocol_t * h,
			u32 * pathlabel)
{
  *pathlabel = h->tcp.seq_ack;
  return HICN_LIB_ERROR_NONE;
}

int
tcp_set_data_pathlabel (hicn_type_t type, hicn_protocol_t * h,
			const u32 pathlabel)
{
  h->tcp.seq_ack = pathlabel;
  return HICN_LIB_ERROR_NONE;
}

int
tcp_update_data_pathlabel (hicn_type_t type, hicn_protocol_t * h,
			   const hicn_faceid_t face_id)
{
  hicn_pathlabel_t pl =
    (hicn_pathlabel_t) ((h->tcp.pathlabel & HICN_PATH_LABEL_MASK) >> (32 -
								      HICN_PATH_LABEL_SIZE));
  hicn_pathlabel_t new_pl;

  update_pathlabel (pl, face_id, &new_pl);
  h->tcp.pathlabel = new_pl;

  return HICN_LIB_ERROR_NONE;
}

int
tcp_reset_data_for_hash (hicn_type_t type, hicn_protocol_t * h)
{
  memset (&(h->tcp), 0, 4);
  memset (&(h->tcp.seq_ack), 0, 12);

  return CHILD_OPS (reset_data_for_hash, type, h);
}


int
tcp_get_lifetime (hicn_type_t type, const hicn_protocol_t * h,
		  hicn_lifetime_t * lifetime)
{
  *lifetime =
    ntohs (h->tcp.urg_ptr) << (h->tcp.data_offset_and_reserved & 0xF);
  return HICN_LIB_ERROR_NONE;
}

int
tcp_set_lifetime (hicn_type_t type, hicn_protocol_t * h,
		  const hicn_lifetime_t lifetime)
{
  u8 multiplier = 0;
  u32 lifetime_scaled = lifetime;

  if (PREDICT_FALSE (lifetime >= HICN_MAX_LIFETIME))
    {
      h->tcp.urg_ptr = htons (HICN_MAX_LIFETIME_SCALED);
      h->tcp.data_offset_and_reserved =
	(h->
	 tcp.data_offset_and_reserved & ~0x0F) | HICN_MAX_LIFETIME_MULTIPLIER;
      return HICN_LIB_ERROR_NONE;
    }

  while (lifetime_scaled > HICN_MAX_LIFETIME_SCALED
	 && multiplier <= HICN_MAX_LIFETIME_MULTIPLIER)
    {
      multiplier++;
      lifetime_scaled = lifetime_scaled >> 1;
    }

  h->tcp.urg_ptr = htons (lifetime_scaled);
  h->tcp.data_offset_and_reserved =
    (h->tcp.data_offset_and_reserved & ~0x0F) | multiplier;

  return HICN_LIB_ERROR_NONE;
}

#if 0
int
tcp_update_checksums (hicn_type_t type, hicn_protocol_t * h, u16 partial_csum,
		      size_t payload_length)
{
  h->tcp.csum = 0;

  if (PREDICT_TRUE (partial_csum != 0))
    {
      partial_csum = ~partial_csum;
    }

  h->tcp.csum = csum (h, TCP_HDRLEN + payload_length, partial_csum);

  return CHILD_OPS (update_checksums, type, h, 0, payload_length);
}

int
tcp_verify_checksums (hicn_type_t type, hicn_protocol_t * h, u16 partial_csum,
		      size_t payload_length)
{
  if (csum (h, TCP_HDRLEN + payload_length, ~partial_csum) != 0)
    return HICN_LIB_ERROR_CORRUPTED_PACKET;
  return CHILD_OPS (verify_checksums, type, h, 0, payload_length);
}
#endif

#define TCP_OFFSET_MASK                13
#define TCP_OFFSET_DATA_OFFSET         12
#define TCP_OFFSET_IN_BITS_DATA_OFFSET 0
#define TCP_OFFSET_IN_BITS_RESERVED    4
#define TCP_OFFSET_IN_BITS_NS          7

#define TCP_DEFAULT_SRC_PORT           0x8000
#define TCP_DEFAULT_DST_PORT           0x0080
#define TCP_DEFAULT_WINDOW_SIZE        0	// In [2, 65535]
#define TCP_DEFAULT_DATA_OFFSET        5	// Size of the TCP header in words (= 4 bytes). Must be greater or equal than 5.
#define TCP_DEFAULT_CWR                0
#define TCP_DEFAULT_ECE                0
#define TCP_DEFAULT_URG                0
#define TCP_DEFAULT_ACK                0
#define TCP_DEFAULT_PSH                0
#define TCP_DEFAULT_RST                0
#define TCP_DEFAULT_SYN                1
#define TCP_DEFAULT_FIN                0

int
tcp_rewrite_interest (hicn_type_t type, hicn_protocol_t * h,
		      const ip46_address_t * addr_new,
		      ip46_address_t * addr_old)
{
  #if 0
  u16 *tcp_checksum = &(h->tcp.csum);

  /*
   * Padding fields are set to zero so we can apply checksum on the
   * whole struct by interpreting it as IPv6 in all cases
   *
   * v4 code would be:
   * csum = ip_csum_sub_even (*tcp_checksum, h->ipv4.saddr.as_u32);
   * csum = ip_csum_add_even (csum, h->ipv4.saddr.as_u32);
   */
  ip_csum_t csum = ip_csum_sub_even (*tcp_checksum, (ip_csum_t) (h->ipv6.saddr.as_u64[0]));
  csum = ip_csum_sub_even (csum, (ip_csum_t) (h->ipv6.saddr.as_u64[1]));
  csum = ip_csum_add_even (csum, (ip_csum_t) (h->ipv6.saddr.as_u64[0]));
  csum = ip_csum_add_even (csum, (ip_csum_t) (h->ipv6.saddr.as_u64[1]));

  *tcp_checksum = ip_csum_fold (csum);
  #endif
  return HICN_LIB_ERROR_NONE;
}

int
tcp_rewrite_data (hicn_type_t type, hicn_protocol_t * h,
		  const ip46_address_t * addr_new, ip46_address_t * addr_old,
		  const hicn_faceid_t face_id)
{
  #if 0
  u16 *tcp_checksum = &(h->tcp.csum);

  /*
   * Padding fields are set to zero so we can apply checksum on the
   * whole struct by interpreting it as IPv6 in all cases
   *
   * v4 code would be:
   * csum = ip_csum_sub_even (*tcp_checksum, h->ipv4.saddr.as_u32);
   * csum = ip_csum_add_even (csum, h->ipv4.saddr.as_u32);
   */
  ip_csum_t csum = ip_csum_sub_even (*tcp_checksum, (ip_csum_t) (addr_old->ip6.as_u64[0]));
  csum = ip_csum_sub_even (*tcp_checksum, (ip_csum_t) (addr_old->ip6.as_u64[1]));
  csum = ip_csum_add_even (csum, (ip_csum_t) (addr_new->ip6.as_u64[0]));
  csum = ip_csum_add_even (csum, (ip_csum_t) (addr_new->ip6.as_u64[1]));

  csum = ip_csum_sub_even (csum, h->tcp.pathlabel);
  tcp_update_data_pathlabel (type, h, face_id);
  csum = ip_csum_add_even (csum, h->tcp.pathlabel);

  *tcp_checksum = ip_csum_fold (csum);
  #endif
  return HICN_LIB_ERROR_NONE;
}

int
tcp_get_current_header_length (hicn_type_t type, const hicn_protocol_t * h,
			       size_t * header_length)
{
  *header_length = TCP_HDRLEN;
  return HICN_LIB_ERROR_NONE;
}

int
tcp_get_header_length (hicn_type_t type, const hicn_protocol_t * h,
		       size_t * header_length)
{
  size_t child_header_length = 0;
  int rc = CHILD_OPS (get_header_length, type, h, &child_header_length);
  if (rc < 0)
    return rc;

  *header_length = TCP_HDRLEN + child_header_length;
  return HICN_LIB_ERROR_NONE;
}

int
tcp_get_signature_size (hicn_type_t type, const hicn_protocol_t * h,
			size_t * signature_size)
{
  return CHILD_OPS (get_signature_size, type, h, signature_size);
}

int
tcp_set_signature_size (hicn_type_t type, hicn_protocol_t * h,
			size_t signature_size)
{
  return CHILD_OPS (set_signature_size, type, h, signature_size);
}

int
tcp_set_signature_timestamp(hicn_type_t type, hicn_protocol_t * h,
       uint64_t signature_timestamp)
{
  return CHILD_OPS (set_signature_timestamp, type, h, signature_timestamp);
}

int
tcp_get_signature_timestamp (hicn_type_t type, const hicn_protocol_t * h,
       uint64_t * signature_timestamp)
{
  return CHILD_OPS (get_signature_timestamp, type, h, signature_timestamp);
}

int
tcp_set_validation_algorithm (hicn_type_t type, hicn_protocol_t * h,
       uint8_t validation_algorithm)
{
  return CHILD_OPS (set_validation_algorithm, type, h, validation_algorithm);
}

int
tcp_get_validation_algorithm (hicn_type_t type, const hicn_protocol_t * h,
       uint8_t * validation_algorithm)
{
  return CHILD_OPS (get_validation_algorithm, type, h, validation_algorithm);
}

int
tcp_set_key_id (hicn_type_t type, hicn_protocol_t * h,
       uint8_t *key_id)
{
  return CHILD_OPS (set_key_id, type, h, key_id);
}

int
tcp_get_key_id (hicn_type_t type, hicn_protocol_t * h,
       uint8_t **key_id, uint8_t *key_id_size)
{
  return CHILD_OPS (get_key_id, type, h, key_id, key_id_size);
}

int
tcp_get_signature (hicn_type_t type, hicn_protocol_t * h,
		              uint8_t ** signature)
{
  return CHILD_OPS (get_signature, type, h, signature);
}

DECLARE_HICN_OPS (tcp);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
