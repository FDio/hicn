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

#include <hicn/transport/core/packet.h>
#include <hicn/transport/utils/literals.h>

#include <core/manifest_format_fixed.h>

namespace transport {

namespace core {

// TODO use preallocated pool of membufs
FixedManifestEncoder::FixedManifestEncoder(Packet &packet,
                                           std::size_t signature_size)
    : packet_(packet),
      max_size_(Packet::default_mtu - packet_.headerSize() - signature_size),
      manifest_(
          utils::MemBuf::create(Packet::default_mtu - packet_.headerSize())),
      manifest_header_(
          reinterpret_cast<ManifestHeader *>(manifest_->writableData())),
      manifest_entries_(reinterpret_cast<ManifestEntry *>(
          manifest_->writableData() + sizeof(ManifestHeader))),
      current_entry_(0),
      signature_size_(signature_size) {
  *manifest_header_ = {0};
}

FixedManifestEncoder::~FixedManifestEncoder() {}

FixedManifestEncoder &FixedManifestEncoder::encodeImpl() {
  manifest_->append(sizeof(ManifestHeader) +
                    manifest_header_->number_of_entries *
                        sizeof(ManifestEntry));
  packet_.appendPayload(std::move(manifest_));
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::clearImpl() {
  manifest_ = utils::MemBuf::create(Packet::default_mtu - packet_.headerSize() -
                                    signature_size_);
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::setHashAlgorithmImpl(
    HashAlgorithm algorithm) {
  manifest_header_->hash_algorithm = static_cast<uint8_t>(algorithm);
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::setManifestTypeImpl(
    ManifestType manifest_type) {
  manifest_header_->manifest_type = static_cast<uint8_t>(manifest_type);
  return *this;
}

FixedManifestEncoder &
FixedManifestEncoder::setNextSegmentCalculationStrategyImpl(
    NextSegmentCalculationStrategy strategy) {
  manifest_header_->next_segment_strategy = static_cast<uint8_t>(strategy);
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::setBaseNameImpl(
    const core::Name &base_name) {
  base_name.copyToDestination(
      reinterpret_cast<uint8_t *>(&manifest_header_->prefix[0]), false);
  manifest_header_->flags.ipv6 =
      base_name.getAddressFamily() == AF_INET6 ? 1_U8 : 0_U8;
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::addSuffixAndHashImpl(
    uint32_t suffix, const utils::CryptoHash &hash) {
  auto _hash = hash.getDigest<std::uint8_t>();
  addSuffixHashBytes(suffix, _hash.data(), _hash.length());
  return *this;
}

void FixedManifestEncoder::addSuffixHashBytes(uint32_t suffix,
                                              const uint8_t *hash,
                                              std::size_t length) {
  manifest_entries_[current_entry_].suffix = htonl(suffix);
  //  std::copy(hash, hash + length,
  //            manifest_entries_[current_entry_].hash);
  std::memcpy(
      reinterpret_cast<uint8_t *>(manifest_entries_[current_entry_].hash), hash,
      length);

  manifest_header_->number_of_entries++;
  current_entry_++;

  if (TRANSPORT_EXPECT_FALSE(estimateSerializedLengthImpl() > max_size_)) {
    throw errors::RuntimeException("Manifest size exceeded the packet MTU!");
  }
}

FixedManifestEncoder &FixedManifestEncoder::setIsFinalManifestImpl(
    bool is_last) {
  manifest_header_->flags.is_last = static_cast<uint8_t>(is_last);
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::setVersionImpl(
    ManifestVersion version) {
  manifest_header_->version = static_cast<uint8_t>(version);
  return *this;
}

std::size_t FixedManifestEncoder::estimateSerializedLengthImpl(
    std::size_t additional_entries) {
  return sizeof(ManifestHeader) +
         (manifest_header_->number_of_entries + additional_entries) *
             sizeof(ManifestEntry);
}

FixedManifestEncoder &FixedManifestEncoder::updateImpl() {
  max_size_ = Packet::default_mtu - packet_.headerSize() - signature_size_;
  return *this;
}

FixedManifestEncoder &FixedManifestEncoder::setFinalBlockNumberImpl(
    std::uint32_t final_block_number) {
  manifest_header_->final_block_number = htonl(final_block_number);
  return *this;
}

std::size_t FixedManifestEncoder::getManifestHeaderSizeImpl() {
  return sizeof(ManifestHeader);
}

std::size_t FixedManifestEncoder::getManifestEntrySizeImpl() {
  return sizeof(ManifestEntry);
}

FixedManifestDecoder::FixedManifestDecoder(Packet &packet)
    : packet_(packet),
      manifest_header_(reinterpret_cast<ManifestHeader *>(
          packet_.getPayload()->writableData())),
      manifest_entries_(reinterpret_cast<ManifestEntry *>(
          packet_.getPayload()->writableData() + sizeof(ManifestHeader))) {}

FixedManifestDecoder::~FixedManifestDecoder() {}

void FixedManifestDecoder::decodeImpl() {
  std::size_t packet_size = packet_.payloadSize();

  if (packet_size < sizeof(ManifestHeader) ||
      packet_size < estimateSerializedLengthImpl()) {
    throw errors::RuntimeException(
        "The packet does not match expected manifest size.");
  }
}

FixedManifestDecoder &FixedManifestDecoder::clearImpl() { return *this; }

ManifestType FixedManifestDecoder::getManifestTypeImpl() const {
  return static_cast<ManifestType>(manifest_header_->manifest_type);
}

HashAlgorithm FixedManifestDecoder::getHashAlgorithmImpl() const {
  return static_cast<HashAlgorithm>(manifest_header_->hash_algorithm);
}

NextSegmentCalculationStrategy
FixedManifestDecoder::getNextSegmentCalculationStrategyImpl() const {
  return static_cast<NextSegmentCalculationStrategy>(
      manifest_header_->next_segment_strategy);
}

typename Fixed::SuffixList FixedManifestDecoder::getSuffixHashListImpl() {
  typename Fixed::SuffixList hash_list;

  for (int i = 0; i < manifest_header_->number_of_entries; i++) {
    hash_list.insert(hash_list.end(),
                     std::make_pair(ntohl(manifest_entries_[i].suffix),
                                    reinterpret_cast<uint8_t *>(
                                        &manifest_entries_[i].hash[0])));
  }

  return hash_list;
}

core::Name FixedManifestDecoder::getBaseNameImpl() const {
  if (static_cast<bool>(manifest_header_->flags.ipv6)) {
    return core::Name(AF_INET6,
                      reinterpret_cast<uint8_t *>(&manifest_header_->prefix));
  } else {
    return core::Name(AF_INET,
                      reinterpret_cast<uint8_t *>(&manifest_header_->prefix));
  }
}

bool FixedManifestDecoder::getIsFinalManifestImpl() const {
  return static_cast<bool>(manifest_header_->flags.is_last);
}

ManifestVersion FixedManifestDecoder::getVersionImpl() const {
  return static_cast<ManifestVersion>(manifest_header_->version);
}

std::size_t FixedManifestDecoder::estimateSerializedLengthImpl(
    std::size_t additional_entries) const {
  return sizeof(ManifestHeader) +
         (additional_entries + manifest_header_->number_of_entries) *
             sizeof(ManifestEntry);
}

uint32_t FixedManifestDecoder::getFinalBlockNumberImpl() const {
  return ntohl(manifest_header_->final_block_number);
}

}  // end namespace core

}  // end namespace transport
