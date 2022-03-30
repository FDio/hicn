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

#include <core/manifest_format_fixed.h>
#include <hicn/transport/core/packet.h>
#include <hicn/transport/utils/literals.h>

namespace transport {

namespace core {

// TODO use preallocated pool of membufs
FixedManifestEncoder::FixedManifestEncoder(Packet &packet,
                                           std::size_t signature_size,
                                           bool clear)
    : packet_(packet),
      max_size_(Packet::default_mtu - packet_.headerSize()),
      signature_size_(signature_size),
      transport_type_(interface::ProductionProtocolAlgorithms::UNKNOWN),
      encoded_(false),
      params_bytestream_({0}),
      params_rtc_({0}) {
  manifest_meta_ = reinterpret_cast<ManifestMeta *>(packet_.writableData() +
                                                    packet_.headerSize());
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

  manifest_meta_->transport_type = static_cast<uint8_t>(transport_type_);
  manifest_entry_meta_->nb_entries = manifest_entries_.size();

  packet_.append(FixedManifestEncoder::manifestHeaderSizeImpl());
  packet_.updateLength();

  switch (transport_type_) {
    case interface::ProductionProtocolAlgorithms::BYTE_STREAM:
      packet_.appendPayload(
          reinterpret_cast<const uint8_t *>(&params_bytestream_),
          MANIFEST_PARAMS_BYTESTREAM_SIZE);
      break;
    case interface::ProductionProtocolAlgorithms::RTC_PROD:
      packet_.appendPayload(reinterpret_cast<const uint8_t *>(&params_rtc_),
                            MANIFEST_PARAMS_RTC_SIZE);
      break;
    default:
      break;
  }

  packet_.appendPayload(
      reinterpret_cast<const uint8_t *>(manifest_entries_.data()),
      manifest_entries_.size() * FixedManifestEncoder::manifestEntrySizeImpl());

  if (TRANSPORT_EXPECT_FALSE(packet_.payloadSize() <
                             estimateSerializedLengthImpl())) {
    throw errors::RuntimeException("Error encoding the manifest");
  }

  encoded_ = true;
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::clearImpl() {
  if (encoded_) {
    packet_.trimEnd(FixedManifestEncoder::manifestHeaderSizeImpl() +
                    manifest_entries_.size() *
                        FixedManifestEncoder::manifestEntrySizeImpl());
  }

  transport_type_ = interface::ProductionProtocolAlgorithms::UNKNOWN;
  encoded_ = false;
  params_bytestream_ = {0};
  params_rtc_ = {0};
  *manifest_meta_ = {0};
  *manifest_entry_meta_ = {0};
  manifest_entries_.clear();

  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::updateImpl() {
  max_size_ = Packet::default_mtu - packet_.headerSize() - signature_size_;
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::setVersionImpl(
    ManifestVersion version) {
  manifest_meta_->version = static_cast<uint8_t>(version);
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::setTypeImpl(
    ManifestType manifest_type) {
  manifest_meta_->type = static_cast<uint8_t>(manifest_type);
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
      .support_fec = params.support_fec,
  };
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::addSuffixAndHashImpl(
    uint32_t suffix, const auth::CryptoHash &hash) {
  std::vector<uint8_t> _hash = hash.getDigest();

  manifest_entries_.push_back(ManifestEntry{
      .suffix = htonl(suffix),
      .hash = {0},
  });

  std::memcpy(reinterpret_cast<uint8_t *>(manifest_entries_.back().hash),
              _hash.data(), _hash.size());

  if (TRANSPORT_EXPECT_FALSE(estimateSerializedLengthImpl() > max_size_)) {
    throw errors::RuntimeException("Manifest size exceeded the packet MTU!");
  }

  return *this;
}

std::size_t FixedManifestEncoder::estimateSerializedLengthImpl(
    std::size_t additional_entries) {
  return FixedManifestEncoder::manifestHeaderSizeImpl(transport_type_) +
         (manifest_entries_.size() + additional_entries) *
             FixedManifestEncoder::manifestEntrySizeImpl();
}

std::size_t FixedManifestEncoder::manifestHeaderSizeImpl(
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

std::size_t FixedManifestEncoder::manifestEntrySizeImpl() {
  return MANIFEST_ENTRY_SIZE;
}

FixedManifestDecoder::FixedManifestDecoder(Packet &packet)
    : packet_(packet), decoded_(false) {
  manifest_meta_ =
      reinterpret_cast<ManifestMeta *>(packet_.getPayload()->writableData());
  manifest_entry_meta_ =
      reinterpret_cast<ManifestEntryMeta *>(manifest_meta_ + 1);
  transport_type_ = getTransportTypeImpl();

  switch (transport_type_) {
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
}

FixedManifestDecoder::~FixedManifestDecoder() {}

void FixedManifestDecoder::decodeImpl() {
  if (decoded_) {
    return;
  }

  std::size_t packet_size = packet_.payloadSize();

  if (packet_size <
          FixedManifestEncoder::manifestHeaderSizeImpl(transport_type_) ||
      packet_size < estimateSerializedLengthImpl()) {
    throw errors::RuntimeException(
        "The packet does not match expected manifest size.");
  }

  decoded_ = true;
}

FixedManifestDecoder &FixedManifestDecoder::clearImpl() {
  decoded_ = false;
  return *this;
}

ManifestType FixedManifestDecoder::getTypeImpl() const {
  return static_cast<ManifestType>(manifest_meta_->type);
}

ManifestVersion FixedManifestDecoder::getVersionImpl() const {
  return static_cast<ManifestVersion>(manifest_meta_->version);
}

interface::ProductionProtocolAlgorithms
FixedManifestDecoder::getTransportTypeImpl() const {
  return static_cast<interface::ProductionProtocolAlgorithms>(
      manifest_meta_->transport_type);
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
      .support_fec = params_rtc_->support_fec,
  };
}

typename Fixed::SuffixList FixedManifestDecoder::getSuffixHashListImpl() {
  typename Fixed::SuffixList hash_list;

  for (int i = 0; i < manifest_entry_meta_->nb_entries; i++) {
    hash_list.insert(hash_list.end(),
                     std::make_pair(ntohl(manifest_entries_[i].suffix),
                                    reinterpret_cast<uint8_t *>(
                                        &manifest_entries_[i].hash[0])));
  }

  return hash_list;
}

std::size_t FixedManifestDecoder::estimateSerializedLengthImpl(
    std::size_t additional_entries) const {
  return FixedManifestEncoder::manifestHeaderSizeImpl(transport_type_) +
         (manifest_entry_meta_->nb_entries + additional_entries) *
             FixedManifestEncoder::manifestEntrySizeImpl();
}

}  // end namespace core

}  // end namespace transport
