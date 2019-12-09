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
#include "udp.h"
#include "tcp.h" // For reused constants

#include "../error.h"
#include "../ops.h"

#define UDP_DEFAULT_SRC_PORT        0x8000 // XXX
#define UDP_DEFAULT_DST_PORT        0x0080 // XXX

DECLARE_get_interest_locator (udp_hicn, UNEXPECTED);
DECLARE_set_interest_locator (udp_hicn, UNEXPECTED);
DECLARE_get_interest_name (udp_hicn, UNEXPECTED);
DECLARE_set_interest_name (udp_hicn, UNEXPECTED);
DECLARE_get_data_locator (udp_hicn, UNEXPECTED);
DECLARE_set_data_locator (udp_hicn, UNEXPECTED);
DECLARE_get_data_name (udp_hicn, UNEXPECTED);
DECLARE_set_data_name (udp_hicn, UNEXPECTED);
DECLARE_get_length (udp_hicn, UNEXPECTED);
DECLARE_get_payload_length (udp_hicn, UNEXPECTED);
DECLARE_set_payload_length (udp_hicn, UNEXPECTED);

int
udp_hicn_init_packet_header (hicn_type_t type, hicn_protocol_t * h)
{
  h->udp_hicn = (_udp_hicn_header_t) {
    .sport = htons (UDP_DEFAULT_SRC_PORT),
    .dport = htons (UDP_DEFAULT_DST_PORT),
    .length = UDP_HDRLEN, // we start with an empty packet
    .csum = 0, // updated below
    .name_suffix = 0,
    .pathlabel = 0,
    .data_offset_and_reserved = TCP_DEFAULT_DATA_OFFSET_RES,
    .flags = TCP_DEFAULT_CWR << 7
           | TCP_DEFAULT_ECE << 6
           | TCP_DEFAULT_URG << 5
           | TCP_DEFAULT_ACK << 4
           | TCP_DEFAULT_PSH << 3
           | TCP_DEFAULT_RST << 2
           | TCP_DEFAULT_SYN << 1
           | TCP_DEFAULT_FIN << 0,
    .window = htons (TCP_DEFAULT_WINDOW_SIZE),
    .csum_unused = 0,
    .urg_ptr = TCP_DEFAULT_URGPTR,
  };

  uint8_t ah_flag = type.l2 == IPPROTO_AH ? AH_FLAG : 0;

  h->udp_hicn.flags |= ah_flag;

  udp_hicn_update_checksums (type, h, 0);

  return CHILD_OPS (init_packet_header, type, h);
}

int
udp_hicn_get_interest_name_suffix (hicn_type_t type, const hicn_protocol_t * h,
			      hicn_name_suffix_t * suffix)
{
  *suffix = ntohl (h->udp_hicn.name_suffix);
  return HICN_LIB_ERROR_NONE;
}

int
udp_hicn_set_interest_name_suffix (hicn_type_t type, hicn_protocol_t * h,
			      const hicn_name_suffix_t * suffix)
{
  h->udp_hicn.name_suffix = htonl (*suffix);

  return HICN_LIB_ERROR_NONE;
}

int
udp_hicn_reset_interest_for_hash (hicn_type_t type, hicn_protocol_t * h)
{
  /* We zero the fields up to name_suffix... */
  memset (&(h->udp_hicn), 0, offsetof(_udp_hicn_header_t, name_suffix));
  /* ... and after from pathlabel */
  memset (&(h->udp_hicn.pathlabel), 0,
          sizeof(_udp_hicn_header_t) - offsetof(_udp_hicn_header_t, pathlabel));

  return CHILD_OPS (reset_interest_for_hash, type, h);
}


int
udp_hicn_get_data_name_suffix (hicn_type_t type, const hicn_protocol_t * h,
			  hicn_name_suffix_t * suffix)
{
  *suffix = ntohl (h->udp_hicn.name_suffix);
  return HICN_LIB_ERROR_NONE;
}

int
udp_hicn_set_data_name_suffix (hicn_type_t type, hicn_protocol_t * h,
			  hicn_name_suffix_t * suffix)
{
  h->udp_hicn.name_suffix = htonl (*suffix);
  return HICN_LIB_ERROR_NONE;
}

int
udp_hicn_get_data_pathlabel (hicn_type_t type, const hicn_protocol_t * h,
			hicn_pathlabel_t * pathlabel)
{
  *pathlabel = h->udp_hicn.pathlabel;
  return HICN_LIB_ERROR_NONE;
}

int
udp_hicn_set_data_pathlabel (hicn_type_t type, hicn_protocol_t * h,
			hicn_pathlabel_t pathlabel)
{
  h->udp_hicn.seq_ack = pathlabel;
  return HICN_LIB_ERROR_NONE;
}

int
udp_hicn_update_data_pathlabel (hicn_type_t type, hicn_protocol_t * h,
			   const hicn_faceid_t face_id)
{
  update_pathlabel(h->udp_hicn.pathlabel, face_id, &h->udp_hicn.pathlabel);
  return HICN_LIB_ERROR_NONE;
}

int
udp_hicn_reset_data_for_hash (hicn_type_t type, hicn_protocol_t * h)
{
  /* We zero the fields up to name_suffix... */
  memset (&(h->udp_hicn), 0, offsetof(_udp_hicn_header_t, name_suffix));
  /* ... and after from pathlabel */
  memset (&(h->udp_hicn.pathlabel), 0,
          sizeof(_udp_hicn_header_t) - offsetof(_udp_hicn_header_t, pathlabel));

  return CHILD_OPS (reset_data_for_hash, type, h);
}


int
udp_hicn_get_lifetime (hicn_type_t type, const hicn_protocol_t * h,
		  hicn_lifetime_t * lifetime)
{
  *lifetime =
    ntohs (h->udp_hicn.lifetime) << (h->udp_hicn.data_offset_and_reserved & 0xF);
  return HICN_LIB_ERROR_NONE;
}

int
udp_hicn_set_lifetime (hicn_type_t type, hicn_protocol_t * h,
		  const hicn_lifetime_t lifetime)
{
  u8 multiplier = 0;
  u32 lifetime_scaled = lifetime;

  if (PREDICT_FALSE (lifetime >= HICN_MAX_LIFETIME))
    {
      h->udp_hicn.lifetime = htons (HICN_MAX_LIFETIME_SCALED);
      h->udp_hicn.data_offset_and_reserved =
	(h->
	 udp_hicn.data_offset_and_reserved & ~0x0F) | HICN_MAX_LIFETIME_MULTIPLIER;
      return HICN_LIB_ERROR_NONE;
    }

  while (lifetime_scaled > HICN_MAX_LIFETIME_SCALED
	 && multiplier <= HICN_MAX_LIFETIME_MULTIPLIER)
    {
      multiplier++;
      lifetime_scaled = lifetime_scaled >> 1;
    }

  h->udp_hicn.lifetime = htons (lifetime_scaled);
  h->udp_hicn.data_offset_and_reserved =
    (h->udp_hicn.data_offset_and_reserved & ~0x0F) | multiplier;

  return HICN_LIB_ERROR_NONE;
}

int
udp_hicn_update_checksums (hicn_type_t type, hicn_protocol_t * h, u16 partial_csum,
		      size_t payload_length)
{
  h->udp_hicn.csum = 0;

  if (PREDICT_TRUE (partial_csum != 0))
    {
      partial_csum = ~partial_csum;
    }

  h->udp_hicn.csum = csum (h, UDP_HDRLEN + payload_length, partial_csum);

  return CHILD_OPS (update_checksums, type, h, 0, payload_length);
}

int
udp_hicn_verify_checksums (hicn_type_t type, hicn_protocol_t * h, u16 partial_csum,
		      size_t payload_length)
{
  if (csum (h, UDP_HDRLEN + payload_length, ~partial_csum) != 0)
    return HICN_LIB_ERROR_CORRUPTED_PACKET;
  return CHILD_OPS (verify_checksums, type, h, 0, payload_length);
}

int
udp_hicn_rewrite_interest (hicn_type_t type, hicn_protocol_t * h,
		      const ip46_address_t * addr_new,
		      ip46_address_t * addr_old)
{
  u16 *udp_hicn_checksum = &(h->udp_hicn.csum);

  /*
   * Padding fields are set to zero so we can apply checksum on the
   * whole struct by interpreting it as IPv6 in all cases
   *
   * v4 code would be:
   * csum = ip_csum_sub_even (*udp_hicn_checksum, h->ipv4.saddr.as_u32);
   * csum = ip_csum_add_even (csum, h->ipv4.saddr.as_u32);
   */
  ip_csum_t csum = ip_csum_sub_even (*udp_hicn_checksum, (ip_csum_t) (h->ipv6.saddr.as_u64[0]));
  csum = ip_csum_sub_even (csum, (ip_csum_t) (h->ipv6.saddr.as_u64[1]));
  csum = ip_csum_add_even (csum, (ip_csum_t) (h->ipv6.saddr.as_u64[0]));
  csum = ip_csum_add_even (csum, (ip_csum_t) (h->ipv6.saddr.as_u64[1]));

  *udp_hicn_checksum = ip_csum_fold (csum);

  return HICN_LIB_ERROR_NONE;
}

int
udp_hicn_rewrite_data (hicn_type_t type, hicn_protocol_t * h,
		  const ip46_address_t * addr_new, ip46_address_t * addr_old,
		  const hicn_faceid_t face_id)
{
  u16 *udp_hicn_checksum = &(h->udp_hicn.csum);

  /*
   * Padding fields are set to zero so we can apply checksum on the
   * whole struct by interpreting it as IPv6 in all cases
   *
   * v4 code would be:
   * csum = ip_csum_sub_even (*udp_hicn_checksum, h->ipv4.saddr.as_u32);
   * csum = ip_csum_add_even (csum, h->ipv4.saddr.as_u32);
   */
  ip_csum_t csum = ip_csum_sub_even (*udp_hicn_checksum, (ip_csum_t) (addr_old->ip6.as_u64[0]));
  csum = ip_csum_sub_even (*udp_hicn_checksum, (ip_csum_t) (addr_old->ip6.as_u64[1]));
  csum = ip_csum_add_even (csum, (ip_csum_t) (addr_new->ip6.as_u64[0]));
  csum = ip_csum_add_even (csum, (ip_csum_t) (addr_new->ip6.as_u64[1]));

  csum = ip_csum_sub_even (csum, h->udp_hicn.pathlabel);
  udp_hicn_update_data_pathlabel (type, h, face_id);
  csum = ip_csum_add_even (csum, h->udp_hicn.pathlabel);

  *udp_hicn_checksum = ip_csum_fold (csum);

  return HICN_LIB_ERROR_NONE;
}

int
udp_hicn_get_current_header_length (hicn_type_t type, const hicn_protocol_t * h,
			       size_t * header_length)
{
  *header_length = UDP_HDRLEN;
  return HICN_LIB_ERROR_NONE;
}

int
udp_hicn_get_header_length (hicn_type_t type, const hicn_protocol_t * h,
		       size_t * header_length)
{
  size_t child_header_length = 0;
  int rc = CHILD_OPS (get_header_length, type, h, &child_header_length);
  if (rc < 0)
    return rc;

  *header_length = UDP_HDRLEN + child_header_length;
  return HICN_LIB_ERROR_NONE;
}

int
udp_hicn_get_signature_size (hicn_type_t type, const hicn_protocol_t * h,
			size_t * signature_size)
{
  return CHILD_OPS (get_signature_size, type, h, signature_size);
}

int
udp_hicn_set_signature_size (hicn_type_t type, hicn_protocol_t * h,
			size_t signature_size)
{
  return CHILD_OPS (set_signature_size, type, h, signature_size);
}

int
udp_hicn_set_signature_timestamp(hicn_type_t type, hicn_protocol_t * h,
       uint64_t signature_timestamp)
{
  return CHILD_OPS (set_signature_timestamp, type, h, signature_timestamp);
}

int
udp_hicn_get_signature_timestamp (hicn_type_t type, const hicn_protocol_t * h,
       uint64_t * signature_timestamp)
{
  return CHILD_OPS (get_signature_timestamp, type, h, signature_timestamp);
}

int
udp_hicn_set_validation_algorithm (hicn_type_t type, hicn_protocol_t * h,
       uint8_t validation_algorithm)
{
  return CHILD_OPS (set_validation_algorithm, type, h, validation_algorithm);
}

int
udp_hicn_get_validation_algorithm (hicn_type_t type, const hicn_protocol_t * h,
       uint8_t * validation_algorithm)
{
  return CHILD_OPS (get_validation_algorithm, type, h, validation_algorithm);
}

int
udp_hicn_set_key_id (hicn_type_t type, hicn_protocol_t * h,
       uint8_t *key_id)
{
  return CHILD_OPS (set_key_id, type, h, key_id);
}

int
udp_hicn_get_key_id (hicn_type_t type, hicn_protocol_t * h,
       uint8_t **key_id, uint8_t *key_id_size)
{
  return CHILD_OPS (get_key_id, type, h, key_id, key_id_size);
}

int
udp_hicn_get_signature (hicn_type_t type, hicn_protocol_t * h,
		              uint8_t ** signature)
{
  return CHILD_OPS (get_signature, type, h, signature);
}

DECLARE_HICN_OPS (udp_hicn);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
