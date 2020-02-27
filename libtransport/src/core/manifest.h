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

#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/name.h>

#include <core/manifest_format.h>

#include <set>

namespace transport {

namespace core {

using typename core::Name;
using typename core::Packet;
using typename core::PayloadType;

template <typename Base, typename FormatTraits, typename ManifestImpl>
class Manifest : public Base {
  static_assert(std::is_base_of<Packet, Base>::value,
                "Base must inherit from packet!");

 public:
  using Encoder = typename FormatTraits::Encoder;
  using Decoder = typename FormatTraits::Decoder;

  Manifest(std::size_t signature_size = 0)
      : Base(HF_INET6_TCP_AH),
        encoder_(*this, signature_size),
        decoder_(*this) {
    Base::setPayloadType(PayloadType::MANIFEST);
  }

  Manifest(const core::Name &name, std::size_t signature_size = 0)
      : Base(name, HF_INET6_TCP_AH),
        encoder_(*this, signature_size),
        decoder_(*this) {
    Base::setPayloadType(PayloadType::MANIFEST);
  }

  template <typename T>
  Manifest(T &&base)
      : Base(std::forward<T &&>(base)), encoder_(*this), decoder_(*this) {
    Base::setPayloadType(PayloadType::MANIFEST);
  }

  virtual ~Manifest() = default;

  std::size_t estimateManifestSize(std::size_t additional_entries = 0) {
    return static_cast<ManifestImpl &>(*this).estimateManifestSizeImpl(
        additional_entries);
  }

  /*
   * After the call to encode, users MUST call clear before adding data
   * to the manifest.
   */
  Manifest &encode() { return static_cast<ManifestImpl &>(*this).encodeImpl(); }

  Manifest &decode() {
    Manifest::decoder_.decode();

    manifest_type_ = decoder_.getManifestType();
    hash_algorithm_ = decoder_.getHashAlgorithm();
    is_last_ = decoder_.getIsFinalManifest();

    return static_cast<ManifestImpl &>(*this).decodeImpl();
  }

  static std::size_t getManifestHeaderSize() {
    return Encoder::getManifestHeaderSize();
  }

  static std::size_t getManifestEntrySize() {
    return Encoder::getManifestEntrySize();
  }

  Manifest &setManifestType(ManifestType type) {
    manifest_type_ = type;
    encoder_.setManifestType(manifest_type_);
    return *this;
  }

  Manifest &setHashAlgorithm(utils::CryptoHashType hash_algorithm) {
    hash_algorithm_ = hash_algorithm;
    encoder_.setHashAlgorithm(hash_algorithm_);
    return *this;
  }

  utils::CryptoHashType getHashAlgorithm() { return hash_algorithm_; }

  ManifestType getManifestType() const { return manifest_type_; }

  bool isFinalManifest() const { return is_last_; }

  Manifest &setVersion(ManifestVersion version) {
    encoder_.setVersion(version);
    return *this;
  }

  Manifest &setFinalBlockNumber(std::uint32_t final_block_number) {
    encoder_.setFinalBlockNumber(final_block_number);
    return *this;
  }

  uint32_t getFinalBlockNumber() const {
    return decoder_.getFinalBlockNumber();
  }

  ManifestVersion getVersion() const { return decoder_.getVersion(); }

  Manifest &setFinalManifest(bool is_final_manifest) {
    encoder_.setIsFinalManifest(is_final_manifest);
    is_last_ = is_final_manifest;
    return *this;
  }

  Manifest &clear() {
    encoder_.clear();
    decoder_.clear();
    return *this;
  }

 protected:
  ManifestType manifest_type_;
  utils::CryptoHashType hash_algorithm_;
  bool is_last_;

  Encoder encoder_;
  Decoder decoder_;
};

}  // end namespace core

}  // end namespace transport
