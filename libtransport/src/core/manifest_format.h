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

#pragma once

#include <hicn/transport/auth/crypto_hash.h>
#include <hicn/transport/core/name.h>
#include <hicn/transport/interfaces/socket_options_keys.h>

#include <cinttypes>
#include <type_traits>
#include <unordered_map>

namespace transport {

namespace core {

enum class ManifestVersion : uint8_t {
  VERSION_1 = 1,
};

enum class ManifestType : uint8_t {
  INLINE_MANIFEST = 1,
  FINAL_CHUNK_NUMBER = 2,
  FLIC_MANIFEST = 3,
};

struct ParamsRTC {
  std::uint64_t timestamp;
  std::uint32_t prod_rate;
  std::uint32_t prod_seg;
  std::uint32_t support_fec;

  bool operator==(const ParamsRTC &other) const {
    return (timestamp == other.timestamp && prod_rate == other.prod_rate &&
            prod_seg == other.prod_seg && support_fec == other.support_fec);
  }
};

struct ParamsBytestream {
  std::uint32_t final_segment;

  bool operator==(const ParamsBytestream &other) const {
    return (final_segment == other.final_segment);
  }
};

template <typename T>
struct format_traits {
  using Encoder = typename T::Encoder;
  using Decoder = typename T::Decoder;
  using Hash = typename T::Hash;
  using HashType = typename T::HashType;
  using Suffix = typename T::Suffix;
  using SuffixList = typename T::SuffixList;
};

class Packet;

template <typename Implementation>
class ManifestEncoder {
 public:
  virtual ~ManifestEncoder() = default;

  ManifestEncoder encode() {
    return static_cast<Implementation &>(*this).encodeImpl();
  }

  ManifestEncoder &clear() {
    return static_cast<Implementation &>(*this).clearImpl();
  }

  ManifestEncoder &setType(ManifestType type) {
    return static_cast<Implementation &>(*this).setTypeImpl(type);
  }

  ManifestEncoder &setHashAlgorithm(auth::CryptoHashType hash) {
    return static_cast<Implementation &>(*this).setHashAlgorithmImpl(hash);
  }

  template <
      typename T,
      typename = std::enable_if_t<std::is_same<
          std::remove_const_t<std::remove_reference_t<T>>, core::Name>::value>>
  ManifestEncoder &setBaseName(T &&name) {
    return static_cast<Implementation &>(*this).setBaseNameImpl(name);
  }

  template <typename Hash>
  ManifestEncoder &addSuffixAndHash(uint32_t suffix, Hash &&hash) {
    return static_cast<Implementation &>(*this).addSuffixAndHashImpl(
        suffix, std::forward<Hash &&>(hash));
  }

  ManifestEncoder &setIsLast(bool is_last) {
    return static_cast<Implementation &>(*this).setIsLastImpl(is_last);
  }

  ManifestEncoder &setVersion(ManifestVersion version) {
    return static_cast<Implementation &>(*this).setVersionImpl(version);
  }

  std::size_t estimateSerializedLength(std::size_t number_of_entries) {
    return static_cast<Implementation &>(*this).estimateSerializedLengthImpl(
        number_of_entries);
  }

  ManifestEncoder &update() {
    return static_cast<Implementation &>(*this).updateImpl();
  }

  ManifestEncoder &setParamsBytestream(const ParamsBytestream &params) {
    return static_cast<Implementation &>(*this).setParamsBytestreamImpl(params);
  }

  ManifestEncoder &setParamsRTC(const ParamsRTC &params) {
    return static_cast<Implementation &>(*this).setParamsRTCImpl(params);
  }

  static std::size_t manifestHeaderSize(
      interface::ProductionProtocolAlgorithms transport_type =
          interface::ProductionProtocolAlgorithms::UNKNOWN) {
    return Implementation::manifestHeaderSizeImpl(transport_type);
  }

  static std::size_t manifestEntrySize() {
    return Implementation::manifestEntrySizeImpl();
  }
};

template <typename Implementation>
class ManifestDecoder {
 public:
  virtual ~ManifestDecoder() = default;

  ManifestDecoder &clear() {
    return static_cast<Implementation &>(*this).clearImpl();
  }

  void decode() { static_cast<Implementation &>(*this).decodeImpl(); }

  ManifestType getType() const {
    return static_cast<const Implementation &>(*this).getTypeImpl();
  }

  interface::ProductionProtocolAlgorithms getTransportType() const {
    return static_cast<const Implementation &>(*this).getTransportTypeImpl();
  }

  auth::CryptoHashType getHashAlgorithm() const {
    return static_cast<const Implementation &>(*this).getHashAlgorithmImpl();
  }

  core::Name getBaseName() const {
    return static_cast<const Implementation &>(*this).getBaseNameImpl();
  }

  auto getSuffixHashList() {
    return static_cast<Implementation &>(*this).getSuffixHashListImpl();
  }

  bool getIsLast() const {
    return static_cast<const Implementation &>(*this).getIsLastImpl();
  }

  ManifestVersion getVersion() const {
    return static_cast<const Implementation &>(*this).getVersionImpl();
  }

  std::size_t estimateSerializedLength(std::size_t number_of_entries) const {
    return static_cast<const Implementation &>(*this)
        .estimateSerializedLengthImpl(number_of_entries);
  }

  ParamsBytestream getParamsBytestream() const {
    return static_cast<const Implementation &>(*this).getParamsBytestreamImpl();
  }

  ParamsRTC getParamsRTC() const {
    return static_cast<const Implementation &>(*this).getParamsRTCImpl();
  }
};

}  // namespace core

}  // namespace transport
