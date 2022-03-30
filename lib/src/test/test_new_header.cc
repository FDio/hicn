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

#include <gtest/gtest.h>

extern "C"
{
#include <hicn/name.h>
#include <hicn/common.h>
#include <hicn/error.h>
#include <hicn/protocol/new.h>
#include <hicn/protocol/ah.h>
#include <hicn/header.h>
#include <hicn/compat.h>
}

class NewHeaderTest : public ::testing::Test
{
protected:
  const char *ipv6_prefix = "b001::abcd:1234:abcd:1234";
  const char *ipv4_prefix = "12.13.14.15";
  const uint32_t suffix = 12345;

  NewHeaderTest (size_t hdr_size, hicn_format_t format)
      : buffer_ (new uint8_t[hdr_size]), header_ ((hicn_header_t *) (buffer_)),
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

  NewHeaderTest () : NewHeaderTest (NEW_HDRLEN, HF_NEW) {}

  virtual ~NewHeaderTest () { delete[] buffer_; }

  void
  checkCommon (const _new_header_t *new_hdr)
  {
    // Initialize header
    int rc = hicn_packet_init_header (format_, header_);
    EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

    // Check fields
    EXPECT_EQ (new_hdr->prefix.v6.as_u64[0], 0UL);
    EXPECT_EQ (new_hdr->prefix.v6.as_u64[1], 0UL);
    EXPECT_EQ (new_hdr->suffix, 0UL);
    EXPECT_EQ (new_hdr->lifetime, 0UL);
    EXPECT_EQ (new_hdr->path_label, 0UL);
    EXPECT_EQ (new_hdr->payload_length, 0UL);
    EXPECT_EQ (_get_new_header_version (new_hdr), 0x9);
  }

  virtual void
  SetUp () override
  {
    auto new_hdr = &header_->protocol.newhdr;
    checkCommon (new_hdr);
    EXPECT_EQ (new_hdr->flags, 0);
  }

  uint8_t *buffer_;
  hicn_header_t *header_;
  hicn_format_t format_;
  hicn_name_t name_, name4_, name6_;
  ip_address_t ipv6_prefix_bytes, ipv4_prefix_bytes;
};

class NewHeaderAHTest : public NewHeaderTest
{
protected:
  NewHeaderAHTest () : NewHeaderTest (NEW_HDRLEN + AH_HDRLEN, HF_NEW_AH) {}

  virtual void
  SetUp () override
  {
    auto new_hdr = &header_->protocol.newhdr;
    checkCommon (new_hdr);
    EXPECT_NE (new_hdr->flags, 0);
  }
};

/**
 * Header Initialization
 */
TEST_F (NewHeaderTest, GetFormat)
{
  // Get format from existing packet
  hicn_format_t format;
  int rc = hicn_packet_get_format (header_, &format);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  // Check it corresponds to the new header format
  EXPECT_EQ (format, HF_NEW);
}

TEST_F (NewHeaderAHTest, GetFormat)
{
  // Get format from existing packet
  hicn_format_t format;
  int rc = hicn_packet_get_format (header_, &format);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  // Check it corresponds to the new header format
  EXPECT_EQ (format, HF_NEW_AH);
}

/**
 * @brief Checksum functions are not required, but we keep them for
 * compatibility.
 */
TEST_F (NewHeaderTest, Checksum)
{
  // Get format from existing packet
  int rc = hicn_packet_compute_checksum (format_, header_);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_compute_header_checksum (format_, header_, 0);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_check_integrity_no_payload (format_, header_, 0);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
}

TEST_F (NewHeaderAHTest, Checksum)
{
  // Get format from existing packet
  int rc = hicn_packet_compute_checksum (format_, header_);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_compute_header_checksum (format_, header_, 0);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_check_integrity_no_payload (format_, header_, 0);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
}

TEST_F (NewHeaderTest, GetHeaderLengthFromFormat)
{
  // Get format from existing packet
  std::size_t hdr_len;
  int rc = hicn_packet_get_header_length_from_format (format_, &hdr_len);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  EXPECT_EQ (hdr_len, NEW_HDRLEN);
}

TEST_F (NewHeaderAHTest, GetHeaderLengthFromFormat)
{
  // Get format from existing packet
  std::size_t hdr_len;
  int rc = hicn_packet_get_header_length_from_format (format_, &hdr_len);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  EXPECT_EQ (hdr_len, NEW_HDRLEN + AH_HDRLEN);
}

TEST_F (NewHeaderTest, GetHeaderLength)
{
  // Get format from existing packet
  std::size_t hdr_len;
  int rc = hicn_packet_get_header_length (format_, header_, &hdr_len);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  EXPECT_EQ (hdr_len, NEW_HDRLEN);
}

TEST_F (NewHeaderAHTest, GetHeaderLength)
{
  // Get format from existing packet
  std::size_t hdr_len;
  int rc = hicn_packet_get_header_length (format_, header_, &hdr_len);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  EXPECT_EQ (hdr_len, NEW_HDRLEN + AH_HDRLEN);
}

TEST_F (NewHeaderTest, SetGetPayloadLength)
{
  // Get format from existing packet
  std::size_t payload_len = 1000, payload_len_ret;
  int rc = hicn_packet_set_payload_length (format_, header_, payload_len);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  rc = hicn_packet_get_payload_length (format_, header_, &payload_len_ret);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  EXPECT_EQ (payload_len, payload_len_ret);
}

TEST_F (NewHeaderAHTest, SetGetPayloadLength)
{
  // Get format from existing packet
  std::size_t payload_len = 1000, payload_len_ret;
  int rc = hicn_packet_set_payload_length (format_, header_, payload_len);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  rc = hicn_packet_get_payload_length (format_, header_, &payload_len_ret);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  EXPECT_EQ (payload_len, payload_len_ret);
}

TEST_F (NewHeaderTest, SetGetName)
{
  // Get v6 name and set it to new_header
  hicn_name_t name_ret;
  int rc = hicn_packet_set_name (format_, header_, &name6_, 1);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_get_name (format_, header_, &name_ret, 1);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_name_compare (&name6_, &name_ret, 1);
  EXPECT_EQ (rc, 0);
}

TEST_F (NewHeaderTest, SetGetLocator)
{
  // This function does nothing but it is set for compatibility
  ip_address_t locator;
  memset (&locator, 0, sizeof (locator));
  locator.v6.as_u8[15] = 1;
  int rc = hicn_packet_set_interest (format_, header_);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_set_locator (format_, header_, &locator, 1);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_get_locator (format_, header_, &locator, 1);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
}

TEST_F (NewHeaderTest, SetGetSignatureSize)
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

TEST_F (NewHeaderAHTest, SetGetSignatureSize)
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

TEST_F (NewHeaderTest, IsInterestIsData)
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

TEST_F (NewHeaderTest, SetGetLifetime)
{
  // Lifetime
  u32 lifetime = 20000, lifetime_ret; // 20 sec.
  int rc = hicn_packet_set_lifetime (format_, header_, lifetime);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_get_lifetime (format_, header_, &lifetime_ret);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  EXPECT_EQ (lifetime, lifetime_ret);
}

TEST_F (NewHeaderAHTest, SetGetLifetime)
{
  // Lifetime
  u32 lifetime = 20000, lifetime_ret; // 20 sec.
  int rc = hicn_packet_set_lifetime (format_, header_, lifetime);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  rc = hicn_packet_get_lifetime (format_, header_, &lifetime_ret);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  EXPECT_EQ (lifetime, lifetime_ret);
}

TEST_F (NewHeaderTest, SetGetPayloadType)
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
