/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

#include <gtest/gtest.h>

extern "C"
{
#include <hicn/name.h>
#include <hicn/common.h>
#include <hicn/error.h>
#include <hicn/packet.h>

#include "../protocol/ah.h"
#include "../protocol/ipv6.h"
#include "../protocol/udp.h"
#include "../protocol/new.h"
}

class UdpHeaderTest : public ::testing::Test
{
protected:
  const char *ipv6_prefix = "b001::abcd:1234:abcd:1234";
  const char *ipv4_prefix = "12.13.14.15";
  const uint32_t suffix = 12345;

  UdpHeaderTest (size_t hdr_size, hicn_packet_format_t format)
      : buffer_ (new uint8_t[hdr_size]), hdr_size_ (hdr_size),
	format_ (format), name_{}, name4_{}, name6_{}
  {
    int rc = inet_pton (AF_INET6, ipv6_prefix, &ipv6_prefix_bytes.v6);
    EXPECT_EQ (rc, 1);

    rc = inet_pton (AF_INET, ipv4_prefix, &ipv4_prefix_bytes.v4);
    EXPECT_EQ (rc, 1);

    rc = hicn_name_create (ipv4_prefix, suffix, &name4_);
    EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
    rc = hicn_name_create (ipv6_prefix, suffix, &name6_);
    EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  }

  UdpHeaderTest ()
      : UdpHeaderTest (NEW_HDRLEN + UDP_HDRLEN + IPV6_HDRLEN,
		       HICN_PACKET_FORMAT_IPV6_UDP)
  {
  }

  virtual ~UdpHeaderTest () { delete[] buffer_; }

  // checked everytime we build the packet...
  void
  checkCommon ()
  {
    /* Initialize packet buffer headers */
    hicn_packet_set_format (&pkbuf_, format_);
    hicn_packet_set_type (&pkbuf_, HICN_PACKET_TYPE_INTEREST);
    hicn_packet_set_buffer (&pkbuf_, buffer_, hdr_size_, 0);
    int rc = hicn_packet_init_header (&pkbuf_, 0);
    EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

    auto ip6_hdr = (_ipv6_header_t *) buffer_;

    // Check fields
    EXPECT_EQ (ip6_hdr->saddr.as_u64[0], 0UL);
    EXPECT_EQ (ip6_hdr->saddr.as_u64[1], 0UL);
    EXPECT_EQ (ip6_hdr->daddr.as_u64[0], 0UL);
    EXPECT_EQ (ip6_hdr->daddr.as_u64[1], 0UL);
    EXPECT_EQ (ip6_hdr->nxt, IPPROTO_UDP);

    _udp_header_t *udp_hdr = (_udp_header_t *) (ip6_hdr + 1);
    EXPECT_EQ (udp_hdr->src_port, 0UL);
    EXPECT_EQ (udp_hdr->dst_port, 0UL);
    EXPECT_EQ (udp_hdr->checksum, 0UL);
    // EXPECT_EQ (ntohs (udp_hdr->length), NEW_HDRLEN + AH_HDRLEN);

    _new_header_t *new_hdr = (_new_header_t *) (udp_hdr + 1);
    EXPECT_EQ (new_hdr->prefix.v6.as_u64[0], 0UL);
    EXPECT_EQ (new_hdr->prefix.v6.as_u64[1], 0UL);
    EXPECT_EQ (new_hdr->suffix, 0UL);
    EXPECT_EQ (new_hdr->lifetime, 0UL);
    EXPECT_EQ (new_hdr->path_label, 0UL);
    EXPECT_EQ (new_hdr->payload_len, 0UL);
    EXPECT_EQ (_get_new_header_version (new_hdr), 0x9);
  }

  virtual void
  SetUp () override
  {
    checkCommon ();
  }

  uint8_t *buffer_;
  size_t hdr_size_;
  hicn_packet_buffer_t pkbuf_;
  hicn_packet_format_t format_;
  hicn_name_t name_, name4_, name6_;
  hicn_ip_address_t ipv6_prefix_bytes, ipv4_prefix_bytes;
};

class UdpHeaderAHTest : public UdpHeaderTest
{
protected:
  UdpHeaderAHTest ()
      : UdpHeaderTest (AH_HDRLEN + NEW_HDRLEN + UDP_HDRLEN + IPV6_HDRLEN,
		       HICN_PACKET_FORMAT_IPV6_UDP_AH)
  {
  }
};

/**
 * Header Initialization
 */
TEST_F (UdpHeaderTest, GetFormat)
{
  hicn_packet_format_t format = hicn_packet_get_format (&pkbuf_);
  EXPECT_EQ (format.as_u32, HICN_PACKET_FORMAT_IPV6_UDP.as_u32);
}

TEST_F (UdpHeaderAHTest, GetFormat)
{
  // Get format from existing packet
  hicn_packet_format_t format = hicn_packet_get_format (&pkbuf_);

  // Check it corresponds to the new header format
  EXPECT_EQ (format.as_u32, HICN_PACKET_FORMAT_IPV6_UDP_AH.as_u32);
}

#if 0

// /**
//  * @brief Checksum functions are not required, but we keep them for
//  * compatibility.
//  */
// TEST_F (NewHeaderTest, Checksum)
// {
//   // Get format from existing packet
//   int rc = hicn_packet_compute_checksum (format_, header_);
//   EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

//   rc = hicn_packet_compute_header_checksum (format_, header_, 0);
//   EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

//   rc = hicn_packet_check_integrity_no_payload (format_, header_, 0);
//   EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
// }

// TEST_F (NewHeaderAHTest, Checksum)
// {
//   // Get format from existing packet
//   int rc = hicn_packet_compute_checksum (format_, header_);
//   EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

//   rc = hicn_packet_compute_header_checksum (format_, header_, 0);
//   EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

//   rc = hicn_packet_check_integrity_no_payload (format_, header_, 0);
//   EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
// }

TEST_F (UdpHeaderTest, GetHeaderLengthFromFormat)
{
  // Get format from existing packet
  std::size_t hdr_len;
  int rc = hicn_packet_get_header_length_from_format (format_, &hdr_len);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  EXPECT_EQ (hdr_len, UDP_HDRLEN + IPV6_HDRLEN + NEW_HDRLEN);
}

TEST_F (UdpHeaderAHTest, GetHeaderLengthFromFormat)
{
  // Get format from existing packet
  std::size_t hdr_len;
  int rc = hicn_packet_get_header_length_from_format (format_, &hdr_len);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  EXPECT_EQ (hdr_len, UDP_HDRLEN + IPV6_HDRLEN + NEW_HDRLEN + AH_HDRLEN);
}

TEST_F (UdpHeaderTest, GetHeaderLength)
{
  // Get format from existing packet
  std::size_t hdr_len;
  int rc = hicn_packet_get_header_length (format_, header_, &hdr_len);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  EXPECT_EQ (hdr_len, UDP_HDRLEN + IPV6_HDRLEN + NEW_HDRLEN);
}

TEST_F (UdpHeaderAHTest, GetHeaderLength)
{
  // Get format from existing packet
  std::size_t hdr_len;
  int rc = hicn_packet_get_header_length (format_, header_, &hdr_len);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  EXPECT_EQ (hdr_len, UDP_HDRLEN + IPV6_HDRLEN + NEW_HDRLEN + AH_HDRLEN);
}

TEST_F (UdpHeaderTest, SetGetPayloadLength)
{
  // Get format from existing packet
  std::size_t payload_len = 1000, payload_len_ret;
  int rc = hicn_packet_set_payload_length (format_, header_, payload_len);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  rc = hicn_packet_get_payload_length (format_, header_, &payload_len_ret);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  EXPECT_EQ (payload_len, payload_len_ret);
}

TEST_F (UdpHeaderAHTest, SetGetPayloadLength)
{
  // Get format from existing packet
  std::size_t payload_len = 1000, payload_len_ret;
  int rc = hicn_packet_set_payload_length (format_, header_, payload_len);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  rc = hicn_packet_get_payload_length (format_, header_, &payload_len_ret);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  EXPECT_EQ (payload_len, payload_len_ret);
}

TEST_F (UdpHeaderTest, SetGetName)
{
  // Get v6 name and set it to new_header
  hicn_name_t name_ret;

  int rc = hicn_packet_set_interest (format_, header_);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_set_name (format_, header_, &name6_, 1);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_get_name (format_, header_, &name_ret, 1);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_name_compare (&name6_, &name_ret, 1);
  EXPECT_EQ (rc, 0);
}

TEST_F (UdpHeaderTest, SetGetLocator)
{
  // This function does nothing but it is set for compatibility
  hicn_ip_address_t locator;
  memset (&locator, 0, sizeof (locator));
  locator.v6.as_u8[15] = 1;
  int rc = hicn_packet_set_interest (format_, header_);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_set_locator (format_, header_, &locator, 1);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_get_locator (format_, header_, &locator, 1);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
}

TEST_F (UdpHeaderTest, SetGetSignatureSize)
{
  // No AH, so we should get an error
  // FixMe no error raised here
  size_t signature_size = 128;
  int rc = hicn_packet_set_signature_size (format_, header_, signature_size);
  (void) rc;
  // EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  // Same for hicn_packet_get_signature_size
  rc = hicn_packet_get_signature_size (format_, header_, &signature_size);
  // EXPECT_NE (rc, HICN_LIB_ERROR_NONE);
}

TEST_F (UdpHeaderAHTest, SetGetSignatureSize)
{
  // No AH, so we should get an error
  size_t signature_size = 128, signature_size_ret;
  int rc = hicn_packet_set_signature_size (format_, header_, signature_size);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  // Same for hicn_packet_get_signature_size
  rc = hicn_packet_get_signature_size (format_, header_, &signature_size_ret);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  EXPECT_EQ (signature_size, signature_size_ret);
}

TEST_F (UdpHeaderTest, IsInterestIsData)
{
  // Mark packet as interest
  int rc = hicn_packet_set_interest (format_, header_);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  int ret;
  rc = hicn_packet_is_interest (format_, header_, &ret);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  EXPECT_EQ (ret, 1);

  // Mark packet as data
  rc = hicn_packet_set_data (format_, header_);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_is_interest (format_, header_, &ret);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  EXPECT_EQ (ret, 0);
}

TEST_F (UdpHeaderTest, SetGetLifetime)
{
  // Lifetime
  u32 lifetime = 20000, lifetime_ret; // 20 sec.
  int rc = hicn_packet_set_lifetime (format_, header_, lifetime);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_get_lifetime (format_, header_, &lifetime_ret);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  EXPECT_EQ (lifetime, lifetime_ret);
}

TEST_F (UdpHeaderAHTest, SetGetLifetime)
{
  // Lifetime
  u32 lifetime = 20000, lifetime_ret; // 20 sec.
  int rc = hicn_packet_set_lifetime (format_, header_, lifetime);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_get_lifetime (format_, header_, &lifetime_ret);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  EXPECT_EQ (lifetime, lifetime_ret);
}

TEST_F (UdpHeaderTest, SetGetPayloadType)
{
  // Lifetime
  hicn_payload_type_t payload_type = HPT_MANIFEST, payload_type_ret;
  int rc = hicn_packet_set_payload_type (format_, header_, payload_type);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_get_payload_type (format_, header_, &payload_type_ret);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  EXPECT_EQ (payload_type, payload_type_ret);

  payload_type = HPT_DATA;

  rc = hicn_packet_set_payload_type (format_, header_, payload_type);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_get_payload_type (format_, header_, &payload_type_ret);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  EXPECT_EQ (payload_type, payload_type_ret);
}
#endif
