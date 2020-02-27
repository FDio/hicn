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

#pragma once

#include <hicn/transport/core/packet.h>

#include <core/manifest_format.h>

#include <string>

namespace transport {

namespace core {

//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |Version| MType |HashAlg|NextStr|     Flags     |NumberOfEntries|
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                       Final Block Number                      |
//  +---------------------------------------------------------------|
//  |                                                               |
//  +                                                               +
//  |                                                               |
//  +                             Prefix                            +
//  |                                                               |
//  +                                                               +
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                             Suffix                            |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                           Hash Value                          |
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class FixedManifestEncoder;
class FixedManifestDecoder;
class Packet;

struct Fixed {
  using Encoder = FixedManifestEncoder;
  using Decoder = FixedManifestDecoder;
  using HashType = utils::CryptoHash;
  using SuffixList = std::list<std::pair<std::uint32_t, std::uint8_t *>>;
};

struct Flags {
  std::uint8_t ipv6 : 1;
  std::uint8_t is_last : 1;
  std::uint8_t unused : 6;
};

struct ManifestEntry {
  std::uint32_t suffix;
  std::uint32_t hash[8];
};

struct ManifestHeader {
  std::uint8_t version : 4;
  std::uint8_t manifest_type : 4;
  std::uint8_t hash_algorithm : 4;
  std::uint8_t next_segment_strategy : 4;
  Flags flags;
  std::uint8_t number_of_entries;
  std::uint32_t final_block_number;
  std::uint32_t prefix[4];
  ManifestEntry entries[0];
};

static const constexpr std::uint8_t manifest_version = 1;

class FixedManifestEncoder : public ManifestEncoder<FixedManifestEncoder> {
 public:
  FixedManifestEncoder(Packet &packet, std::size_t signature_size = 0);

  ~FixedManifestEncoder();

  FixedManifestEncoder &encodeImpl();

  FixedManifestEncoder &clearImpl();

  FixedManifestEncoder &setManifestTypeImpl(ManifestType manifest_type);

  FixedManifestEncoder &setHashAlgorithmImpl(utils::CryptoHashType algorithm);

  FixedManifestEncoder &setNextSegmentCalculationStrategyImpl(
      NextSegmentCalculationStrategy strategy);

  FixedManifestEncoder &setBaseNameImpl(const core::Name &base_name);

  FixedManifestEncoder &addSuffixAndHashImpl(uint32_t suffix,
                                             const utils::CryptoHash &hash);

  FixedManifestEncoder &setIsFinalManifestImpl(bool is_last);

  FixedManifestEncoder &setVersionImpl(ManifestVersion version);

  std::size_t estimateSerializedLengthImpl(std::size_t additional_entries = 0);

  FixedManifestEncoder &updateImpl();

  FixedManifestEncoder &setFinalBlockNumberImpl(
      std::uint32_t final_block_number);

  static std::size_t getManifestHeaderSizeImpl();

  static std::size_t getManifestEntrySizeImpl();

 private:
  void addSuffixHashBytes(uint32_t suffix, const uint8_t *hash,
                          std::size_t length);

  Packet &packet_;
  std::size_t max_size_;
  std::unique_ptr<utils::MemBuf> manifest_;
  ManifestHeader *manifest_header_;
  ManifestEntry *manifest_entries_;
  std::size_t current_entry_;
  std::size_t signature_size_;
};

class FixedManifestDecoder : public ManifestDecoder<FixedManifestDecoder> {
 public:
  FixedManifestDecoder(Packet &packet);

  ~FixedManifestDecoder();

  void decodeImpl();

  FixedManifestDecoder &clearImpl();

  ManifestType getManifestTypeImpl() const;

  utils::CryptoHashType getHashAlgorithmImpl() const;

  NextSegmentCalculationStrategy getNextSegmentCalculationStrategyImpl() const;

  typename Fixed::SuffixList getSuffixHashListImpl();

  core::Name getBaseNameImpl() const;

  bool getIsFinalManifestImpl() const;

  std::size_t estimateSerializedLengthImpl(
      std::size_t additional_entries = 0) const;

  ManifestVersion getVersionImpl() const;

  uint32_t getFinalBlockNumberImpl() const;

 private:
  Packet &packet_;
  ManifestHeader *manifest_header_;
  ManifestEntry *manifest_entries_;
};

}  // namespace core

}  // namespace transport
