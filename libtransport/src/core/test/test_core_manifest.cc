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

#include <gtest/gtest.h>

#include "../manifest_format_fixed.h"
#include "../manifest_inline.h"

#include <test.h>
#include <random>
#include <vector>

namespace transport {

namespace core {

namespace {
// The fixture for testing class Foo.
class ManifestTest : public ::testing::Test {
 protected:
  using ContentObjectManifest = ManifestInline<ContentObject, Fixed>;

  ManifestTest() : name_("b001::123|321"), manifest1_(name_) {
    // You can do set-up work for each test here.
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

  Name name_;
  ContentObjectManifest manifest1_;

  std::vector<uint8_t> manifest_payload = {
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

TEST_F(ManifestTest, ManifestCreate) {
  ContentObjectManifest manifest2(name_);
  ContentObjectManifest manifest3 = manifest2;

  EXPECT_EQ(manifest1_, manifest2);
  EXPECT_EQ(manifest1_, manifest3);
}

TEST_F(ManifestTest, ManifestCreateFromBase) {
  ContentObject content_object(name_);
  content_object.setPayload(manifest_payload.data(), manifest_payload.size());
  ContentObjectManifest manifest(std::move(content_object));

  auto manifest4 = ContentObjectManifest::createManifest(
      name_, core::ManifestVersion::VERSION_1,
      core::ManifestType::INLINE_MANIFEST, HashAlgorithm::SHA_256, true,
      core::Name("b001::dead"),
      core::NextSegmentCalculationStrategy::INCREMENTAL, 128);

  manifest4->encode();
  manifest4->dump();
  manifest.dump();

  EXPECT_EQ(manifest1_, manifest);
  //  EXPECT_EQ(manifest1_, manifest3);
}

TEST_F(ManifestTest, SetLastManifest) {
  manifest1_.clear();

  manifest1_.setFinalManifest(true);
  manifest1_.encode();
  manifest1_.decode();
  bool fcn = manifest1_.isFinalManifest();

  ASSERT_TRUE(fcn);
}

TEST_F(ManifestTest, SetManifestType) {
  manifest1_.clear();

  ManifestType type1 = ManifestType::INLINE_MANIFEST;
  ManifestType type2 = ManifestType::FLIC_MANIFEST;

  manifest1_.setManifestType(type1);
  manifest1_.encode();
  manifest1_.decode();
  ManifestType type_returned1 = manifest1_.getManifestType();

  manifest1_.clear();

  manifest1_.setManifestType(type2);
  manifest1_.encode();
  manifest1_.decode();
  ManifestType type_returned2 = manifest1_.getManifestType();

  ASSERT_EQ(type1, type_returned1);
  ASSERT_EQ(type2, type_returned2);
}

TEST_F(ManifestTest, SetHashAlgorithm) {
  manifest1_.clear();

  HashAlgorithm hash1 = HashAlgorithm::SHA_512;
  HashAlgorithm hash2 = HashAlgorithm::CRC32C;
  HashAlgorithm hash3 = HashAlgorithm::SHA_256;

  manifest1_.setHashAlgorithm(hash1);
  manifest1_.encode();
  manifest1_.decode();
  HashAlgorithm type_returned1 = manifest1_.getHashAlgorithm();

  manifest1_.clear();

  manifest1_.setHashAlgorithm(hash2);
  manifest1_.encode();
  manifest1_.decode();
  HashAlgorithm type_returned2 = manifest1_.getHashAlgorithm();

  manifest1_.clear();

  manifest1_.setHashAlgorithm(hash3);
  manifest1_.encode();
  manifest1_.decode();
  HashAlgorithm type_returned3 = manifest1_.getHashAlgorithm();

  ASSERT_EQ(hash1, type_returned1);
  ASSERT_EQ(hash2, type_returned2);
  ASSERT_EQ(hash3, type_returned3);
}

TEST_F(ManifestTest, SetNextSegmentCalculationStrategy) {
  manifest1_.clear();

  NextSegmentCalculationStrategy strategy1 =
      NextSegmentCalculationStrategy::INCREMENTAL;

  manifest1_.setNextSegmentCalculationStrategy(strategy1);
  manifest1_.encode();
  manifest1_.decode();
  NextSegmentCalculationStrategy type_returned1 =
      manifest1_.getNextSegmentCalculationStrategy();

  ASSERT_EQ(strategy1, type_returned1);
}

TEST_F(ManifestTest, SetBaseName) {
  manifest1_.clear();

  core::Name base_name("b001::dead");
  manifest1_.setBaseName(base_name);
  manifest1_.encode();
  manifest1_.decode();
  core::Name ret_name = manifest1_.getBaseName();

  ASSERT_EQ(base_name, ret_name);
}

TEST_F(ManifestTest, SetSuffixList) {
  manifest1_.clear();

  core::Name base_name("b001::dead");

  using random_bytes_engine =
      std::independent_bits_engine<std::default_random_engine, CHAR_BIT,
                                   unsigned char>;
  random_bytes_engine rbe;

  std::default_random_engine eng((std::random_device())());
  std::uniform_int_distribution<uint64_t> idis(
      0, std::numeric_limits<uint32_t>::max());

  auto entries = new std::pair<uint32_t, utils::CryptoHash>[3];
  uint32_t suffixes[3];
  std::vector<unsigned char> data[3];

  for (int i = 0; i < 3; i++) {
    data[i].resize(32);
    std::generate(std::begin(data[i]), std::end(data[i]), std::ref(rbe));
    suffixes[i] = idis(eng);
    entries[i] = std::make_pair(
        suffixes[i], utils::CryptoHash(data[i].data(), data[i].size(),
                                       utils::CryptoHashType::SHA_256));
    manifest1_.addSuffixHash(entries[i].first, entries[i].second);
  }

  manifest1_.setBaseName(base_name);

  manifest1_.encode();
  manifest1_.decode();

  core::Name ret_name = manifest1_.getBaseName();

  // auto & hash_list = manifest1_.getSuffixHashList();

  bool cond;
  int i = 0;

  // for (auto & item : manifest1_.getSuffixList()) {
  //   auto hash = manifest1_.getHash(suffixes[i]);
  //   cond = utils::CryptoHash::compareBinaryDigest(hash,
  //                                                 entries[i].second.getDigest<uint8_t>().data(),
  //                                                 entries[i].second.getType());
  //   ASSERT_TRUE(cond);
  //   i++;
  // }

  ASSERT_EQ(base_name, ret_name);

  delete[] entries;
}

TEST_F(ManifestTest, EstimateSize) {
  manifest1_.clear();

  HashAlgorithm hash1 = HashAlgorithm::SHA_256;
  NextSegmentCalculationStrategy strategy1 =
      NextSegmentCalculationStrategy::INCREMENTAL;
  ManifestType type1 = ManifestType::INLINE_MANIFEST;
  core::Name base_name1("b001:abcd:fede:baba:cece:d0d0:face:dead");

  manifest1_.setFinalManifest(true);
  manifest1_.setBaseName(base_name1);
  manifest1_.setNextSegmentCalculationStrategy(strategy1);
  manifest1_.setHashAlgorithm(hash1);
  manifest1_.setManifestType(type1);

  std::default_random_engine eng((std::random_device())());
  std::uniform_int_distribution<uint64_t> idis(
      0, std::numeric_limits<uint64_t>::max());

  using random_bytes_engine =
      std::independent_bits_engine<std::default_random_engine, CHAR_BIT,
                                   unsigned char>;
  random_bytes_engine rbe;

  while (manifest1_.estimateManifestSize(1) < 1440) {
    uint32_t suffix = static_cast<std::uint32_t>(idis(eng));
    std::vector<unsigned char> data(32);
    std::generate(std::begin(data), std::end(data), std::ref(rbe));
    auto hash = utils::CryptoHash(data.data(), data.size(),
                                  utils::CryptoHashType::SHA_256);
    manifest1_.addSuffixHash(suffix, hash);
  }

  manifest1_.encode();
  manifest1_.decode();

  manifest1_.dump();

  ASSERT_GT(manifest1_.estimateManifestSize(), 0);
  ASSERT_LT(manifest1_.estimateManifestSize(), 1500);
}

}  // namespace core

}  // namespace transport

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}