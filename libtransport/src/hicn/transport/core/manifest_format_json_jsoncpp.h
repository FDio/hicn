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

#include <hicn/transport/core/manifest_format.h>
#include <hicn/transport/core/name.h>

#if defined(__APPLE__) || defined(__ANDROID__)
#include <json/json.h>
#else
#include <jsoncpp/json/json.h>
#endif /* __APPLE__  || __ANDROID__*/

#include <string>

namespace transport {

namespace core {

class JSONManifestEncoder;
class JSONManifestDecoder;
class Packet;

struct JSON {
  using Encoder = JSONManifestEncoder;
  using Decoder = JSONManifestDecoder;
  using HashType = utils::CryptoHash;
  using SuffixList = std::unordered_map<std::uint32_t, std::uint8_t *>;
};

template <typename T>
struct JSONKey;

template <>
struct JSONKey<ManifestVersion> {
  static const constexpr char *key = "manifest_version";
};

template <>
struct JSONKey<HashAlgorithm> {
  static const constexpr char *key = "hash_algorithm";
};

template <>
struct JSONKey<ManifestType> {
  static const constexpr char *key = "manifest_type";
};

template <>
struct JSONKey<NextSegmentCalculationStrategy> {
  static const constexpr char *key = "next_segment_strategy";
};

template <>
struct JSONKey<typename JSON::SuffixList> {
  static const constexpr char *key = "suffix_hash_list";
};

template <>
struct JSONKey<core::Name> {
  static const constexpr char *key = "base_name";
};

template <>
struct JSONKey<bool> {
  static const constexpr char *final_manifest = "final_manifest";
};

class JSONManifestEncoder : public ManifestEncoder<JSONManifestEncoder> {
 public:
  JSONManifestEncoder(Packet &packet);

  ~JSONManifestEncoder() override;

  JSONManifestEncoder &encodeImpl();

  JSONManifestEncoder &clearImpl();

  JSONManifestEncoder &setManifestTypeImpl(ManifestType manifest_type);

  JSONManifestEncoder &setHashAlgorithmImpl(HashAlgorithm algorithm);

  JSONManifestEncoder &setNextSegmentCalculationStrategyImpl(
      NextSegmentCalculationStrategy strategy);

  JSONManifestEncoder &setSuffixHashListImpl(
      const typename JSON::SuffixList &name_hash_list);

  JSONManifestEncoder &setBaseNameImpl(const core::Name &base_name);

  JSONManifestEncoder &addSuffixAndHashImpl(uint32_t suffix,
                                            const utils::CryptoHash &hash);

  JSONManifestEncoder &setIsFinalManifestImpl(bool is_last);

  JSONManifestEncoder &setVersionImpl(ManifestVersion version);

  std::size_t estimateSerializedLengthImpl(std::size_t number_of_entries);

  JSONManifestEncoder &updateImpl();

  JSONManifestEncoder &setFinalBlockNumberImpl(
      std::uint32_t final_block_number);

  static std::size_t getManifestHeaderSizeImpl();

 private:
  Packet &packet_;
  Json::Value root_;
};

class JSONManifestDecoder : public ManifestDecoder<JSONManifestDecoder> {
 public:
  JSONManifestDecoder(Packet &packet);

  ~JSONManifestDecoder() override;

  void decodeImpl();

  JSONManifestDecoder &clearImpl();

  ManifestType getManifestTypeImpl() const;

  HashAlgorithm getHashAlgorithmImpl() const;

  uint32_t getFinalChunkImpl() const;

  NextSegmentCalculationStrategy getNextSegmentCalculationStrategyImpl() const;

  typename JSON::SuffixList getSuffixHashListImpl();

  core::Name getBaseNameImpl() const;

  bool getIsFinalManifestImpl() const;

  std::size_t estimateSerializedLengthImpl(std::size_t number_of_entries) const;

  ManifestVersion getVersionImpl() const;

  uint32_t getFinalBlockNumberImpl() const;

 private:
  Packet &packet_;
  Json::Value root_;
};

}  // namespace core

}  // namespace transport