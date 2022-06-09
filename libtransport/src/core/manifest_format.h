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
#include <protocols/fec_utils.h>

#include <cinttypes>
#include <type_traits>
#include <unordered_map>

namespace transport {
namespace core {

enum class ManifestType : uint8_t {
  INLINE_MANIFEST = 1,
  FINAL_CHUNK_NUMBER = 2,
  FLIC_MANIFEST = 3,
};

struct ParamsRTC {
  std::uint64_t timestamp;
  std::uint32_t prod_rate;
  std::uint32_t prod_seg;
  protocol::fec::FECType fec_type;

  bool operator==(const ParamsRTC &other) const {
    return (timestamp == other.timestamp && prod_rate == other.prod_rate &&
            prod_seg == other.prod_seg && fec_type == other.fec_type);
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

  bool isEncoded() const {
    return static_cast<const Implementation &>(*this).isEncodedImpl();
  }

  ManifestEncoder &setType(ManifestType type) {
    return static_cast<Implementation &>(*this).setTypeImpl(type);
  }

  ManifestEncoder &setMaxCapacity(uint8_t max_capacity) {
    return static_cast<Implementation &>(*this).setMaxCapacityImpl(
        max_capacity);
  }

  ManifestEncoder &setHashAlgorithm(auth::CryptoHashType hash) {
    return static_cast<Implementation &>(*this).setHashAlgorithmImpl(hash);
  }

  ManifestEncoder &setIsLast(bool is_last) {
    return static_cast<Implementation &>(*this).setIsLastImpl(is_last);
  }

  template <
      typename T,
      typename = std::enable_if_t<std::is_same<
          std::remove_const_t<std::remove_reference_t<T>>, core::Name>::value>>
  ManifestEncoder &setBaseName(T &&name) {
    return static_cast<Implementation &>(*this).setBaseNameImpl(name);
  }

  ManifestEncoder &setParamsBytestream(const ParamsBytestream &params) {
    return static_cast<Implementation &>(*this).setParamsBytestreamImpl(params);
  }

  ManifestEncoder &setParamsRTC(const ParamsRTC &params) {
    return static_cast<Implementation &>(*this).setParamsRTCImpl(params);
  }

  template <typename Hash>
  ManifestEncoder &addEntry(uint32_t suffix, Hash &&hash) {
    return static_cast<Implementation &>(*this).addEntryImpl(
        suffix, std::forward<Hash>(hash));
  }

  ManifestEncoder &removeEntry(uint32_t suffix) {
    return static_cast<Implementation &>(*this).removeEntryImpl(suffix);
  }

  std::size_t manifestHeaderSize() const {
    return static_cast<const Implementation &>(*this).manifestHeaderSizeImpl();
  }

  std::size_t manifestPayloadSize(size_t additional_entries = 0) const {
    return static_cast<const Implementation &>(*this).manifestPayloadSizeImpl(
        additional_entries);
  }

  std::size_t manifestSize(size_t additional_entries = 0) const {
    return static_cast<const Implementation &>(*this).manifestSizeImpl(
        additional_entries);
  }
};

template <typename Implementation>
class ManifestDecoder {
 public:
  virtual ~ManifestDecoder() = default;

  ManifestDecoder &decode() {
    return static_cast<Implementation &>(*this).decodeImpl();
  }

  ManifestDecoder &clear() {
    return static_cast<Implementation &>(*this).clearImpl();
  }

  bool isDecoded() const {
    return static_cast<const Implementation &>(*this).isDecodedImpl();
  }

  ManifestType getType() const {
    return static_cast<const Implementation &>(*this).getTypeImpl();
  }

  interface::ProductionProtocolAlgorithms getTransportType() const {
    return static_cast<const Implementation &>(*this).getTransportTypeImpl();
  }

  uint8_t getMaxCapacity() const {
    return static_cast<const Implementation &>(*this).getMaxCapacityImpl();
  }

  auth::CryptoHashType getHashAlgorithm() const {
    return static_cast<const Implementation &>(*this).getHashAlgorithmImpl();
  }

  bool getIsLast() const {
    return static_cast<const Implementation &>(*this).getIsLastImpl();
  }

  core::Name getBaseName() const {
    return static_cast<const Implementation &>(*this).getBaseNameImpl();
  }

  ParamsBytestream getParamsBytestream() const {
    return static_cast<const Implementation &>(*this).getParamsBytestreamImpl();
  }

  ParamsRTC getParamsRTC() const {
    return static_cast<const Implementation &>(*this).getParamsRTCImpl();
  }

  auto getEntries() const {
    return static_cast<const Implementation &>(*this).getEntriesImpl();
  }

  std::size_t manifestHeaderSize() const {
    return static_cast<const Implementation &>(*this).manifestHeaderSizeImpl();
  }

  std::size_t manifestPayloadSize(size_t additional_entries = 0) const {
    return static_cast<const Implementation &>(*this).manifestPayloadSizeImpl(
        additional_entries);
  }

  std::size_t manifestSize(size_t additional_entries = 0) const {
    return static_cast<const Implementation &>(*this).manifestSizeImpl(
        additional_entries);
  }
};

}  // namespace core
}  // namespace transport
