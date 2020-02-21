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

#include <hicn/transport/core/name.h>
#include <hicn/transport/security/crypto_hasher.h>

#include <cinttypes>
#include <type_traits>
#include <unordered_map>

namespace transport {

namespace core {

enum class ManifestFields : uint8_t {
  VERSION,
  HASH_ALGORITHM,
  SEGMENT_CALCULATION_STRATEGY,
  FINAL_MANIFEST,
  NAME_HASH_LIST,
  BASE_NAME
};

enum class ManifestVersion : uint8_t {
  VERSION_1 = 1,
};

enum class ManifestType : uint8_t {
  INLINE_MANIFEST = 1,
  FINAL_CHUNK_NUMBER = 2,
  FLIC_MANIFEST = 3,
};

enum class HashAlgorithm : uint8_t {
  SHA_256 = static_cast<uint8_t>(utils::CryptoHashType::SHA_256),
  SHA_512 = static_cast<uint8_t>(utils::CryptoHashType::SHA_512),
  CRC32C = static_cast<uint8_t>(utils::CryptoHashType::CRC32C),
};

/**
 * INCREMENTAL: Manifests will be received inline with the data with no specific
 * assumption regarding the manifest capacity. Consumers can send interests
 * using a +1 heuristic.
 *
 * MANIFEST_CAPACITY_BASED: manifests with capacity N have a suffix multiple of
 * N+1: 0, N+1, 2(N+1) etc. Contents have a suffix incremented by 1 except when
 * it conflicts with a manifest: 1, 2, ..., N, N+2, N+3, ..., 2N+1, 2N+3
 */
enum class NextSegmentCalculationStrategy : uint8_t {
  INCREMENTAL = 1,
  MANIFEST_CAPACITY_BASED = 2,
};

template <typename T>
struct format_traits {
  using Encoder = typename T::Encoder;
  using Decoder = typename T::Decoder;
  using HashType = typename T::HashType;
  using HashList = typename T::HashList;
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

  ManifestEncoder &setManifestType(ManifestType type) {
    return static_cast<Implementation &>(*this).setManifestTypeImpl(type);
  }

  ManifestEncoder &setHashAlgorithm(HashAlgorithm hash) {
    return static_cast<Implementation &>(*this).setHashAlgorithmImpl(hash);
  }

  ManifestEncoder &setFinalChunkNumber(uint32_t final_chunk) {
    return static_cast<Implementation &>(*this).setFinalChunkImpl(final_chunk);
  }

  ManifestEncoder &setNextSegmentCalculationStrategy(
      NextSegmentCalculationStrategy strategy) {
    return static_cast<Implementation &>(*this)
        .setNextSegmentCalculationStrategyImpl(strategy);
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

  ManifestEncoder &setIsFinalManifest(bool is_last) {
    return static_cast<Implementation &>(*this).setIsFinalManifestImpl(is_last);
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

  ManifestEncoder &setFinalBlockNumber(std::uint32_t final_block_number) {
    return static_cast<Implementation &>(*this).setFinalBlockNumberImpl(
        final_block_number);
  }

  static std::size_t getManifestHeaderSize() {
    return Implementation::getManifestHeaderSizeImpl();
  }

  static std::size_t getManifestEntrySize() {
    return Implementation::getManifestEntrySizeImpl();
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

  ManifestType getManifestType() const {
    return static_cast<const Implementation &>(*this).getManifestTypeImpl();
  }

  HashAlgorithm getHashAlgorithm() const {
    return static_cast<const Implementation &>(*this).getHashAlgorithmImpl();
  }

  uint32_t getFinalChunkNumber() const {
    return static_cast<const Implementation &>(*this).getFinalChunkImpl();
  }

  NextSegmentCalculationStrategy getNextSegmentCalculationStrategy() const {
    return static_cast<const Implementation &>(*this)
        .getNextSegmentCalculationStrategyImpl();
  }

  core::Name getBaseName() const {
    return static_cast<const Implementation &>(*this).getBaseNameImpl();
  }

  auto getSuffixHashList() {
    return static_cast<Implementation &>(*this).getSuffixHashListImpl();
  }

  bool getIsFinalManifest() const {
    return static_cast<const Implementation &>(*this).getIsFinalManifestImpl();
  }

  ManifestVersion getVersion() const {
    return static_cast<const Implementation &>(*this).getVersionImpl();
  }

  std::size_t estimateSerializedLength(std::size_t number_of_entries) const {
    return static_cast<const Implementation &>(*this)
        .estimateSerializedLengthImpl(number_of_entries);
  }

  uint32_t getFinalBlockNumber() const {
    return static_cast<const Implementation &>(*this).getFinalBlockNumberImpl();
  }
};

}  // namespace core

}  // namespace transport
