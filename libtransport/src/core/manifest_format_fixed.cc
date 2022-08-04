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

#include <core/manifest_format_fixed.h>
#include <hicn/transport/core/packet.h>
#include <hicn/transport/utils/literals.h>

namespace transport {
namespace core {

// ---------------------------------------------------------
// FixedManifest
// ---------------------------------------------------------
size_t FixedManifest::manifestHeaderSize(
    interface::ProductionProtocolAlgorithms transport_type) {
  uint32_t params_size = 0;

  switch (transport_type) {
    case interface::ProductionProtocolAlgorithms::BYTE_STREAM:
      params_size = MANIFEST_PARAMS_BYTESTREAM_SIZE;
      break;
    case interface::ProductionProtocolAlgorithms::RTC_PROD:
      params_size = MANIFEST_PARAMS_RTC_SIZE;
      break;
    default:
      break;
  }

  return MANIFEST_META_SIZE + MANIFEST_ENTRY_META_SIZE + params_size;
}

size_t FixedManifest::manifestPayloadSize(size_t nb_entries) {
  return nb_entries * MANIFEST_ENTRY_SIZE;
}

// ---------------------------------------------------------
// FixedManifestEncoder
// ---------------------------------------------------------
FixedManifestEncoder::FixedManifestEncoder(Packet::Ptr packet, bool clear)
    : packet_(packet),
      transport_type_(interface::ProductionProtocolAlgorithms::UNKNOWN),
      encoded_(false) {
  manifest_meta_ = reinterpret_cast<ManifestMeta *>(packet_->writableData() +
                                                    packet_->headerSize());
  manifest_entry_meta_ =
      reinterpret_cast<ManifestEntryMeta *>(manifest_meta_ + 1);

  if (clear) {
    *manifest_meta_ = {0};
    *manifest_entry_meta_ = {0};
  }
}

FixedManifestEncoder::~FixedManifestEncoder() {}

FixedManifestEncoder &FixedManifestEncoder::encodeImpl() {
  if (encoded_) {
    return *this;
  }

  // Copy manifest header
  manifest_meta_->transport_type = static_cast<uint8_t>(transport_type_);
  manifest_entry_meta_->nb_entries = manifest_entries_.size();

  packet_->append(manifestHeaderSizeImpl());

  packet_->updateLength();
  auto params = reinterpret_cast<uint8_t *>(manifest_entry_meta_ + 1);

  switch (transport_type_) {
    case interface::ProductionProtocolAlgorithms::BYTE_STREAM: {
      auto bytestream = reinterpret_cast<const uint8_t *>(&params_bytestream_);
      std::memcpy(params, bytestream, MANIFEST_PARAMS_BYTESTREAM_SIZE);
      break;
    }
    case interface::ProductionProtocolAlgorithms::RTC_PROD: {
      auto rtc = reinterpret_cast<const uint8_t *>(&params_rtc_);
      std::memcpy(params, rtc, MANIFEST_PARAMS_RTC_SIZE);
      break;
    }
    default:
      break;
  }

  // Copy manifest entries
  auto payload = reinterpret_cast<const uint8_t *>(manifest_entries_.data());
  packet_->appendPayload(payload, manifestPayloadSizeImpl());

  packet_->updateLength();
  if (TRANSPORT_EXPECT_FALSE(packet_->payloadSize() < manifestSizeImpl())) {
    throw errors::RuntimeException("Error encoding the manifest");
  }

  encoded_ = true;
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::clearImpl() {
  if (encoded_) {
    packet_->trimEnd(manifestSizeImpl());
  }

  transport_type_ = interface::ProductionProtocolAlgorithms::UNKNOWN;
  encoded_ = false;
  *manifest_meta_ = {0};
  *manifest_entry_meta_ = {0};
  params_bytestream_ = {0};
  params_rtc_ = {0};
  manifest_entries_.clear();

  return *this;
}

bool FixedManifestEncoder::isEncodedImpl() const { return encoded_; }

FixedManifestEncoder &FixedManifestEncoder::setTypeImpl(
    ManifestType manifest_type) {
  manifest_meta_->type = static_cast<uint8_t>(manifest_type);
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::setMaxCapacityImpl(
    uint8_t max_capacity) {
  manifest_meta_->max_capacity = max_capacity;
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::setHashAlgorithmImpl(
    auth::CryptoHashType algorithm) {
  manifest_meta_->hash_algorithm = static_cast<uint8_t>(algorithm);
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::setIsLastImpl(bool is_last) {
  manifest_meta_->is_last = static_cast<uint8_t>(is_last);
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::setBaseNameImpl(
    const core::Name &base_name) {
  manifest_entry_meta_->is_ipv6 =
      base_name.getAddressFamily() == AF_INET6 ? 1_U8 : 0_U8;
  base_name.copyPrefixToDestination(
      reinterpret_cast<uint8_t *>(&manifest_entry_meta_->prefix[0]));
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::setParamsBytestreamImpl(
    const ParamsBytestream &params) {
  transport_type_ = interface::ProductionProtocolAlgorithms::BYTE_STREAM;
  params_bytestream_ = TransportParamsBytestream{
      .final_segment = params.final_segment,
  };
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::setParamsRTCImpl(
    const ParamsRTC &params) {
  transport_type_ = interface::ProductionProtocolAlgorithms::RTC_PROD;
  params_rtc_ = TransportParamsRTC{
      .timestamp = params.timestamp,
      .prod_rate = params.prod_rate,
      .prod_seg = params.prod_seg,
      .fec_type = static_cast<uint32_t>(params.fec_type),
  };
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::addEntryImpl(
    uint32_t suffix, const auth::CryptoHash &hash) {
  ManifestEntry last_entry = {
      .suffix = portability::host_to_net(suffix),
      .hash = {0},
  };

  auto last_hash = reinterpret_cast<uint8_t *>(last_entry.hash);
  std::memcpy(last_hash, hash.getDigest()->data(), hash.getSize());

  manifest_entries_.push_back(last_entry);
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::removeEntryImpl(uint32_t suffix) {
  for (auto it = manifest_entries_.begin(); it != manifest_entries_.end();) {
    if (it->suffix == suffix)
      it = manifest_entries_.erase(it);
    else
      ++it;
  }
  return *this;
}

size_t FixedManifestEncoder::manifestHeaderSizeImpl() const {
  return FixedManifest::manifestHeaderSize(transport_type_);
}

size_t FixedManifestEncoder::manifestPayloadSizeImpl(
    size_t additional_entries) const {
  return FixedManifest::manifestPayloadSize(manifest_entries_.size() +
                                            additional_entries);
}

size_t FixedManifestEncoder::manifestSizeImpl(size_t additional_entries) const {
  return manifestHeaderSizeImpl() + manifestPayloadSizeImpl(additional_entries);
}

// ---------------------------------------------------------
// FixedManifestDecoder
// ---------------------------------------------------------
FixedManifestDecoder::FixedManifestDecoder(Packet::Ptr packet)
    : packet_(packet), decoded_(false) {
  manifest_meta_ =
      reinterpret_cast<ManifestMeta *>(packet_->getPayload()->writableData());
  manifest_entry_meta_ =
      reinterpret_cast<ManifestEntryMeta *>(manifest_meta_ + 1);
}

FixedManifestDecoder::~FixedManifestDecoder() {}

FixedManifestDecoder &FixedManifestDecoder::decodeImpl() {
  if (decoded_) {
    return *this;
  }

  if (packet_->payloadSize() < manifestSizeImpl()) {
    throw errors::RuntimeException(
        "The packet payload size does not match expected manifest size");
  }

  switch (getTransportTypeImpl()) {
    case interface::ProductionProtocolAlgorithms::BYTE_STREAM:
      params_bytestream_ = reinterpret_cast<TransportParamsBytestream *>(
          manifest_entry_meta_ + 1);
      manifest_entries_ =
          reinterpret_cast<ManifestEntry *>(params_bytestream_ + 1);
      break;
    case interface::ProductionProtocolAlgorithms::RTC_PROD:
      params_rtc_ =
          reinterpret_cast<TransportParamsRTC *>(manifest_entry_meta_ + 1);
      manifest_entries_ = reinterpret_cast<ManifestEntry *>(params_rtc_ + 1);
      break;
    default:
      manifest_entries_ =
          reinterpret_cast<ManifestEntry *>(manifest_entry_meta_ + 1);
      break;
  }

  decoded_ = true;
  return *this;
}

FixedManifestDecoder &FixedManifestDecoder::clearImpl() {
  decoded_ = false;
  return *this;
}

bool FixedManifestDecoder::isDecodedImpl() const { return decoded_; }

ManifestType FixedManifestDecoder::getTypeImpl() const {
  return static_cast<ManifestType>(manifest_meta_->type);
}

interface::ProductionProtocolAlgorithms
FixedManifestDecoder::getTransportTypeImpl() const {
  return static_cast<interface::ProductionProtocolAlgorithms>(
      manifest_meta_->transport_type);
}

uint8_t FixedManifestDecoder::getMaxCapacityImpl() const {
  return manifest_meta_->max_capacity;
}

auth::CryptoHashType FixedManifestDecoder::getHashAlgorithmImpl() const {
  return static_cast<auth::CryptoHashType>(manifest_meta_->hash_algorithm);
}

bool FixedManifestDecoder::getIsLastImpl() const {
  return static_cast<bool>(manifest_meta_->is_last);
}

core::Name FixedManifestDecoder::getBaseNameImpl() const {
  if (static_cast<bool>(manifest_entry_meta_->is_ipv6)) {
    return core::Name(
        AF_INET6, reinterpret_cast<uint8_t *>(&manifest_entry_meta_->prefix));
  } else {
    return core::Name(
        AF_INET, reinterpret_cast<uint8_t *>(&manifest_entry_meta_->prefix));
  }
}

ParamsBytestream FixedManifestDecoder::getParamsBytestreamImpl() const {
  return ParamsBytestream{
      .final_segment = params_bytestream_->final_segment,
  };
}

ParamsRTC FixedManifestDecoder::getParamsRTCImpl() const {
  return ParamsRTC{
      .timestamp = params_rtc_->timestamp,
      .prod_rate = params_rtc_->prod_rate,
      .prod_seg = params_rtc_->prod_seg,
      .fec_type = static_cast<protocol::fec::FECType>(params_rtc_->fec_type),
  };
}

typename Fixed::SuffixList FixedManifestDecoder::getEntriesImpl() const {
  typename Fixed::SuffixList hash_list;

  for (int i = 0; i < manifest_entry_meta_->nb_entries; i++) {
    hash_list.insert(
        hash_list.end(),
        std::make_pair(
            portability::net_to_host(manifest_entries_[i].suffix),
            reinterpret_cast<uint8_t *>(&manifest_entries_[i].hash[0])));
  }

  return hash_list;
}

size_t FixedManifestDecoder::manifestHeaderSizeImpl() const {
  interface::ProductionProtocolAlgorithms type = getTransportTypeImpl();
  return FixedManifest::manifestHeaderSize(type);
}

size_t FixedManifestDecoder::manifestPayloadSizeImpl(
    size_t additional_entries) const {
  size_t nb_entries = manifest_entry_meta_->nb_entries + additional_entries;
  return FixedManifest::manifestPayloadSize(nb_entries);
}

size_t FixedManifestDecoder::manifestSizeImpl(size_t additional_entries) const {
  return manifestHeaderSizeImpl() + manifestPayloadSizeImpl(additional_entries);
}

}  // end namespace core
}  // end namespace transport
