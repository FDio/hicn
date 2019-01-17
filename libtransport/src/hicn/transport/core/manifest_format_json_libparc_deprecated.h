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

extern "C" {
#include <parc/algol/parc_JSON.h>
}

#include <string>

namespace transport {

namespace core {

class JSONManifestEncoder;
class JSONManifestDecoder;
class Packet;

struct JSON {
  using Encoder = JSONManifestEncoder;
  using Decoder = JSONManifestDecoder;
};

template <typename T>
struct JSONKey;

template <>
struct JSONKey<HashAlgorithm> {
  static const constexpr char* key = "hash_algorithm";
};

template <>
struct JSONKey<ManifestType> {
  static const constexpr char* key = "manifest_type";
};

template <>
struct JSONKey<NextSegmentCalculationStrategy> {
  static const constexpr char* key = "next_segment_strategy";
};

template <>
struct JSONKey<NameHashList> {
  static const constexpr char* key = "name_hash_list";
};

template <>
struct JSONKey<SuffixHashList> {
  static const constexpr char* key = "suffix_hash_list";
};

template <>
struct JSONKey<core::Name> {
  static const constexpr char* key = "base_name";
};

template <>
struct JSONKey<bool> {
  static const constexpr char* final_manifest = "final_manifest";
};

// template <>
// struct JSONKey<base_name> {
//  static const std::string key = "name_hash_list";
//};

// namespace JSONManifestEncoding {
//  static const std::string base_name = "base_name";
//  static const std::string final_chunk_number = "final_chunk_number";
//  static const std::string hash_algorithm = "hash_algorithm";
//  static const std::string manifest_type = "manifest_type";
//  static const std::string name_hash_list = "name_hash_list";
//  static const std::string next_segment_strategy = "next_segment_strategy";
//}

class JSONManifestEncoder : public ManifestEncoder<JSONManifestEncoder> {
 public:
  JSONManifestEncoder();

  ~JSONManifestEncoder();

  JSONManifestEncoder& encodeImpl(Packet& packet);

  JSONManifestEncoder& clearImpl();

  JSONManifestEncoder& setManifestTypeImpl(ManifestType manifest_type);

  JSONManifestEncoder& setHashAlgorithmImpl(HashAlgorithm algorithm);

  JSONManifestEncoder& setNextSegmentCalculationStrategyImpl(
      NextSegmentCalculationStrategy strategy);

  JSONManifestEncoder& setSuffixHashListImpl(
      const SuffixHashList& name_hash_list);

  JSONManifestEncoder& setBaseNameImpl(const core::Name& base_name);

  JSONManifestEncoder& addSuffixAndHashImpl(uint32_t suffix, uint64_t hash);

  JSONManifestEncoder& setIsFinalManifestImpl(bool is_last);

 private:
  PARCJSON* root_;
};

class JSONManifestDecoder : public ManifestDecoder<JSONManifestDecoder> {
 public:
  JSONManifestDecoder();

  ~JSONManifestDecoder();

  void decodeImpl(const uint8_t* payload, std::size_t payload_size);

  JSONManifestDecoder& clearImpl();

  ManifestType getManifestTypeImpl() const;

  HashAlgorithm getHashAlgorithmImpl() const;

  uint32_t getFinalChunkImpl() const;

  NextSegmentCalculationStrategy getNextSegmentCalculationStrategyImpl() const;

  SuffixHashList getSuffixHashListImpl();

  core::Name getBaseNameImpl() const;

  bool getIsFinalManifestImpl();

 private:
  PARCJSON* root_;
};

}  // namespace core

}  // namespace transport