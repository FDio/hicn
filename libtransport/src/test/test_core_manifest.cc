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

#include <core/manifest.h>
#include <core/manifest_format_fixed.h>
#include <gtest/gtest.h>
#include <hicn/transport/auth/crypto_hash.h>
#include <hicn/transport/auth/signer.h>
#include <hicn/transport/auth/verifier.h>
#include <test/packet_samples.h>

#include <climits>
#include <random>
#include <vector>

namespace transport {

namespace core {

namespace {
// The fixture for testing class Foo.
class ManifestTest : public ::testing::Test {
 protected:
  using ContentObjectManifest = Manifest<Fixed>;

  ManifestTest()
      : format_(HICN_PACKET_FORMAT_IPV6_TCP_AH),
        name_("b001::123|321"),
        signature_size_(0) {
    manifest_ = ContentObjectManifest::createContentManifest(format_, name_,
                                                             signature_size_);
  }

  virtual ~ManifestTest() {
    // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up
  // and cleaning up each test, you can define the following methods:

  virtual void SetUp() {
    // Code here will be called immediately after the constructor (right
    // before each test).
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test (right
    // before the destructor).
  }

  Packet::Format format_;
  Name name_;
  std::size_t signature_size_;
  std::shared_ptr<ContentObjectManifest> manifest_;
  std::vector<uint8_t> manifest_payload_ = {
      0x11, 0x11, 0x01, 0x00, 0xb0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad  // , 0x00, 0x00,
                                                            // 0x00, 0x45, 0xa3,
                                                            // 0xd1, 0xf2, 0x2b,
                                                            // 0x94, 0x41, 0x22,
                                                            // 0xc9, 0x00, 0x00,
                                                            // 0x00, 0x44, 0xa3,
                                                            // 0xd1, 0xf2, 0x2b,
                                                            // 0x94, 0x41, 0x22,
                                                            // 0xc8
  };
};

}  // namespace

TEST_F(ManifestTest, ManifestConstructor) {
  // Create content object with manifest in payload
  ContentObject::Ptr co =
      core::PacketManager<>::getInstance().getPacket<ContentObject>(
          format_, signature_size_);
  co->setName(name_);
  co->appendPayload(manifest_payload_.data(), manifest_payload_.size());

  uint8_t buffer[256] = {0};
  co->appendPayload(buffer, 256);

  // Copy packet payload
  uint8_t packet[1500];
  auto length = co->getPayload()->length();
  std::memcpy(packet, co->getPayload()->data(), length);

  // Create manifest
  ContentObjectManifest manifest(co);

  // Check manifest payload is exactly the same of content object
  ASSERT_EQ(length, manifest.getPacket()->getPayload()->length());
  auto ret =
      std::memcmp(packet, manifest.getPacket()->getPayload()->data(), length);
  ASSERT_EQ(ret, 0);
}

TEST_F(ManifestTest, SetManifestType) {
  manifest_->Encoder::clear();

  ManifestType type1 = ManifestType::INLINE_MANIFEST;
  ManifestType type2 = ManifestType::FLIC_MANIFEST;

  manifest_->setType(type1);
  ManifestType type_returned1 = manifest_->getType();

  manifest_->Encoder::clear();

  manifest_->setType(type2);
  ManifestType type_returned2 = manifest_->getType();

  ASSERT_EQ(type1, type_returned1);
  ASSERT_EQ(type2, type_returned2);
}

TEST_F(ManifestTest, SetMaxCapacity) {
  manifest_->Encoder::clear();

  uint8_t max_capacity1 = 0;
  uint8_t max_capacity2 = 20;

  manifest_->setMaxCapacity(max_capacity1);
  uint8_t max_capacity_returned1 = manifest_->getMaxCapacity();

  manifest_->Encoder::clear();

  manifest_->setMaxCapacity(max_capacity2);
  uint8_t max_capacity_returned2 = manifest_->getMaxCapacity();

  ASSERT_EQ(max_capacity1, max_capacity_returned1);
  ASSERT_EQ(max_capacity2, max_capacity_returned2);
}

TEST_F(ManifestTest, SetHashAlgorithm) {
  manifest_->Encoder::clear();

  auth::CryptoHashType hash1 = auth::CryptoHashType::SHA256;
  auth::CryptoHashType hash2 = auth::CryptoHashType::SHA512;
  auth::CryptoHashType hash3 = auth::CryptoHashType::BLAKE2B512;

  manifest_->setHashAlgorithm(hash1);
  auto type_returned1 = manifest_->getHashAlgorithm();

  manifest_->Encoder::clear();

  manifest_->setHashAlgorithm(hash2);
  auto type_returned2 = manifest_->getHashAlgorithm();

  manifest_->Encoder::clear();

  manifest_->setHashAlgorithm(hash3);
  auto type_returned3 = manifest_->getHashAlgorithm();

  ASSERT_EQ(hash1, type_returned1);
  ASSERT_EQ(hash2, type_returned2);
  ASSERT_EQ(hash3, type_returned3);
}

TEST_F(ManifestTest, SetLastManifest) {
  manifest_->Encoder::clear();

  manifest_->setIsLast(true);
  bool is_last = manifest_->getIsLast();

  ASSERT_TRUE(is_last);
}

TEST_F(ManifestTest, SetBaseName) {
  manifest_->Encoder::clear();

  core::Name base_name("b001::dead");

  manifest_->setBaseName(base_name);
  core::Name ret_name = manifest_->getBaseName();

  ASSERT_EQ(base_name, ret_name);
}

TEST_F(ManifestTest, setParamsBytestream) {
  manifest_->Encoder::clear();

  ParamsBytestream params{
      .final_segment = 0x0a,
  };

  manifest_->setParamsBytestream(params);
  auth::CryptoHash hash(auth::CryptoHashType::SHA256);
  hash.computeDigest({0x01, 0x02, 0x03, 0x04});
  manifest_->addEntry(1, hash);

  manifest_->encode();
  manifest_->decode();

  auto transport_type_returned = manifest_->getTransportType();
  auto params_returned = manifest_->getParamsBytestream();

  ASSERT_EQ(interface::ProductionProtocolAlgorithms::BYTE_STREAM,
            transport_type_returned);
  ASSERT_EQ(params, params_returned);
}

TEST_F(ManifestTest, SetParamsRTC) {
  manifest_->Encoder::clear();

  ParamsRTC params{
      .timestamp = 0x0a,
      .prod_rate = 0x0b,
      .prod_seg = 0x0c,
      .fec_type = protocol::fec::FECType::UNKNOWN,
  };

  manifest_->setParamsRTC(params);
  auth::CryptoHash hash(auth::CryptoHashType::SHA256);
  hash.computeDigest({0x01, 0x02, 0x03, 0x04});
  manifest_->addEntry(1, hash);

  manifest_->encode();
  manifest_->decode();

  auto transport_type_returned = manifest_->getTransportType();
  auto params_returned = manifest_->getParamsRTC();

  ASSERT_EQ(interface::ProductionProtocolAlgorithms::RTC_PROD,
            transport_type_returned);
  ASSERT_EQ(params, params_returned);
}

TEST_F(ManifestTest, SignManifest) {
  auto signer = std::make_shared<auth::SymmetricSigner>(
      auth::CryptoSuite::HMAC_SHA256, "hunter2");
  auto verifier = std::make_shared<auth::SymmetricVerifier>("hunter2");

  // Instantiate manifest
  uint8_t max_capacity = 30;
  std::shared_ptr<ContentObjectManifest> manifest =
      ContentObjectManifest::createContentManifest(
          format_, name_, signer->getSignatureFieldSize());
  manifest->setHeaders(ManifestType::INLINE_MANIFEST, max_capacity,
                       signer->getHashType(), false /* is_last */, name_);

  // Add manifest entry
  auth::CryptoHash hash(signer->getHashType());
  hash.computeDigest({0x01, 0x02, 0x03, 0x04});
  manifest->addEntry(1, hash);

  // Encode manifest
  manifest->encode();
  auto manifest_co =
      std::dynamic_pointer_cast<ContentObject>(manifest->getPacket());

  // Sign manifest
  signer->signPacket(manifest_co.get());

  // Check size
  ASSERT_EQ(manifest_co->payloadSize(), manifest->Encoder::manifestSize());
  ASSERT_EQ(manifest_co->length(),
            manifest_co->headerSize() + manifest_co->payloadSize());

  // Verify manifest
  auth::VerificationPolicy policy = verifier->verifyPackets(manifest_co.get());
  ASSERT_EQ(auth::VerificationPolicy::ACCEPT, policy);
}

TEST_F(ManifestTest, SetSuffixList) {
  manifest_->Encoder::clear();

  using random_bytes_engine =
      std::independent_bits_engine<std::default_random_engine, CHAR_BIT,
                                   unsigned char>;
  random_bytes_engine rbe;

  std::default_random_engine eng((std::random_device())());
  std::uniform_int_distribution<uint64_t> idis(
      0, std::numeric_limits<uint32_t>::max());

  auto entries = new std::pair<uint32_t, auth::CryptoHash>[3];
  uint32_t suffixes[3];
  std::vector<unsigned char> data[3];

  for (int i = 0; i < 3; i++) {
    data[i].resize(32);
    std::generate(std::begin(data[i]), std::end(data[i]), std::ref(rbe));
    suffixes[i] = idis(eng);
    entries[i] = std::make_pair(suffixes[i],
                                auth::CryptoHash(data[i].data(), data[i].size(),
                                                 auth::CryptoHashType::SHA256));
    manifest_->addEntry(entries[i].first, entries[i].second);
  }

  core::Name base_name("b001::dead");
  manifest_->setBaseName(base_name);

  core::Name ret_name = manifest_->getBaseName();
  ASSERT_EQ(base_name, ret_name);

  delete[] entries;
}

}  // namespace core

}  // namespace transport
