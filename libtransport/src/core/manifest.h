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

#include <core/manifest_format.h>
#include <glog/logging.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/name.h>

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
  // core::ContentObjectManifest::Ptr

  using Encoder = typename FormatTraits::Encoder;
  using Decoder = typename FormatTraits::Decoder;

  Manifest(Packet::Format format, std::size_t signature_size = 0)
      : Base(format, signature_size),
        encoder_(*this, signature_size),
        decoder_(*this) {
    DCHECK(_is_ah(format));
    Base::setPayloadType(PayloadType::MANIFEST);
  }

  Manifest(Packet::Format format, const core::Name &name,
           std::size_t signature_size = 0)
      : Base(name, format, signature_size),
        encoder_(*this, signature_size),
        decoder_(*this) {
    DCHECK(_is_ah(format));
    Base::setPayloadType(PayloadType::MANIFEST);
  }

  template <typename T>
  Manifest(T &&base)
      : Base(std::forward<T &&>(base)),
        encoder_(*this, 0, false),
        decoder_(*this) {
    Base::setPayloadType(PayloadType::MANIFEST);
  }

  // Useful for decoding manifests while avoiding packet copy
  template <typename T>
  Manifest(T &base)
      : Base(base.getFormat()), encoder_(base, 0, false), decoder_(base) {}

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

    manifest_type_ = decoder_.getType();
    manifest_transport_type_ = decoder_.getTransportType();
    hash_algorithm_ = decoder_.getHashAlgorithm();
    is_last_ = decoder_.getIsLast();

    return static_cast<ManifestImpl &>(*this).decodeImpl();
  }

  static std::size_t manifestHeaderSize(
      interface::ProductionProtocolAlgorithms transport_type =
          interface::ProductionProtocolAlgorithms::UNKNOWN) {
    return Encoder::manifestHeaderSize(transport_type);
  }

  static std::size_t manifestEntrySize() {
    return Encoder::manifestEntrySize();
  }

  Manifest &setType(ManifestType type) {
    manifest_type_ = type;
    encoder_.setType(manifest_type_);
    return *this;
  }

  Manifest &setHashAlgorithm(auth::CryptoHashType hash_algorithm) {
    hash_algorithm_ = hash_algorithm;
    encoder_.setHashAlgorithm(hash_algorithm_);
    return *this;
  }

  auth::CryptoHashType getHashAlgorithm() const { return hash_algorithm_; }

  ManifestType getType() const { return manifest_type_; }

  interface::ProductionProtocolAlgorithms getTransportType() const {
    return manifest_transport_type_;
  }

  bool getIsLast() const { return is_last_; }

  Manifest &setVersion(ManifestVersion version) {
    encoder_.setVersion(version);
    return *this;
  }

  Manifest &setParamsBytestream(const ParamsBytestream &params) {
    manifest_transport_type_ =
        interface::ProductionProtocolAlgorithms::BYTE_STREAM;
    encoder_.setParamsBytestream(params);
    return *this;
  }

  Manifest &setParamsRTC(const ParamsRTC &params) {
    manifest_transport_type_ =
        interface::ProductionProtocolAlgorithms::RTC_PROD;
    encoder_.setParamsRTC(params);
    return *this;
  }

  ParamsBytestream getParamsBytestream() const {
    return decoder_.getParamsBytestream();
  }

  ParamsRTC getParamsRTC() const { return decoder_.getParamsRTC(); }

  ManifestVersion getVersion() const { return decoder_.getVersion(); }

  Manifest &setIsLast(bool is_last) {
    encoder_.setIsLast(is_last);
    is_last_ = is_last;
    return *this;
  }

  Manifest &clear() {
    encoder_.clear();
    decoder_.clear();
    return *this;
  }

 protected:
  ManifestType manifest_type_;
  interface::ProductionProtocolAlgorithms manifest_transport_type_;
  auth::CryptoHashType hash_algorithm_;
  bool is_last_;

  Encoder encoder_;
  Decoder decoder_;
};

}  // end namespace core

}  // end namespace transport
