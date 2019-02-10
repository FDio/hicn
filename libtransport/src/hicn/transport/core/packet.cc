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
#include <hicn/transport/errors/malformed_packet_exception.h>
#include <hicn/transport/utils/hash.h>
#include <hicn/transport/utils/log.h>

extern "C" {
#ifndef _WIN32
TRANSPORT_CLANG_DISABLE_WARNING("-Wextern-c-compat")
#endif
#include <hicn/error.h>
}

namespace transport {

namespace core {

const core::Name Packet::base_name("0::0|0");

Packet::Packet(Format format)
    : packet_(utils::MemBuf::create(getHeaderSizeFromFormat(format, 256))
                  .release()),
      packet_start_(packet_->writableData()),
      header_head_(packet_.get()),
      payload_head_(nullptr),
      format_(format) {
  if (hicn_packet_init_header(format, (hicn_header_t *)packet_start_) < 0) {
    throw errors::RuntimeException("Unexpected error initializing the packet.");
  }

  packet_->append(getHeaderSizeFromFormat(format_));
}

Packet::Packet(MemBufPtr &&buffer)
    : packet_(std::move(buffer)),
      packet_start_(packet_->writableData()),
      header_head_(packet_.get()),
      payload_head_(nullptr),
      format_(getFormatFromBuffer(packet_start_)) {
  int signature_size = 0;
  if (_is_ah(format_)) {
    signature_size = (uint32_t)getSignatureSize();
  }

  auto header_size = getHeaderSizeFromFormat(format_, signature_size);

  auto payload_length = packet_->length() - header_size - signature_size;

  if (!payload_length) {
    return;
  }

  packet_->trimEnd(packet_->length());

  if (payload_length) {
    auto payload = packet_->cloneOne();
    payload_head_ = payload.get();
    payload_head_->advance(header_size + signature_size);
    payload_head_->append(payload_length);
    packet_->prependChain(std::move(payload));
    packet_->append(header_size);
  }
}

Packet::Packet(const uint8_t *buffer, std::size_t size)
    : Packet(MemBufPtr(utils::MemBuf::copyBuffer(buffer, size).release())) {}

Packet::Packet(Packet &&other)
    : packet_(std::move(other.packet_)),
      packet_start_(packet_->writableData()),
      header_head_(other.header_head_),
      payload_head_(other.payload_head_),
      format_(other.format_) {
  other.packet_start_ = nullptr;
  other.header_head_ = nullptr;
  other.payload_head_ = nullptr;
  other.format_ = HF_UNSPEC;
}

Packet::~Packet() {}

std::size_t Packet::getHeaderSizeFromFormat(Format format,
                                            size_t signature_size) {
  std::size_t header_length;
  hicn_packet_get_header_length_from_format(format, &header_length);
  int is_ah = _is_ah(format);
  return is_ah * (header_length + signature_size) + (!is_ah) * header_length;
}

std::size_t Packet::getHeaderSizeFromBuffer(Format format,
                                            const uint8_t *buffer) {
  size_t header_length;
  if (hicn_packet_get_header_length(format, (hicn_header_t *)buffer,
                                    &header_length) < 0) {
    throw errors::MalformedPacketException();
  }
  return header_length;
}

bool Packet::isInterest(const uint8_t *buffer) {
  bool is_interest = false;

  if (TRANSPORT_EXPECT_FALSE(hicn_packet_test_ece((const hicn_header_t *)buffer,
                                                  &is_interest) < 0)) {
    throw errors::RuntimeException(
        "Impossible to retrieve ece flag from packet");
  }

  return !is_interest;
}

Packet::Format Packet::getFormatFromBuffer(const uint8_t *buffer) {
  Format format = HF_UNSPEC;

  if (TRANSPORT_EXPECT_FALSE(
          hicn_packet_get_format((const hicn_header_t *)buffer, &format) < 0)) {
    throw errors::MalformedPacketException();
  }

  return format;
}

std::size_t Packet::getPayloadSizeFromBuffer(Format format,
                                             const uint8_t *buffer) {
  std::size_t payload_length;
  if (TRANSPORT_EXPECT_FALSE(
          hicn_packet_get_payload_length(format, (hicn_header_t *)buffer,
                                         &payload_length) < 0)) {
    throw errors::MalformedPacketException();
  }

  return payload_length;
}

std::size_t Packet::payloadSize() const {
  return getPayloadSizeFromBuffer(format_, packet_start_);
}

std::size_t Packet::headerSize() const {
  return getHeaderSizeFromBuffer(format_, packet_start_);
}

const uint8_t *Packet::start() const { return packet_start_; }

void Packet::setLifetime(uint32_t lifetime) {
  if (hicn_interest_set_lifetime((hicn_header_t *)packet_start_, lifetime) <
      0) {
    throw errors::MalformedPacketException();
  }
}

uint32_t Packet::getLifetime() const {
  uint32_t lifetime = 0;

  if (hicn_packet_get_lifetime((hicn_header_t *)packet_start_, &lifetime) < 0) {
    throw errors::MalformedPacketException();
  }

  return lifetime;
}

Packet &Packet::appendPayload(std::unique_ptr<utils::MemBuf> &&payload) {
  if (!payload_head_) {
    payload_head_ = payload.get();
  }

  header_head_->prependChain(std::move(payload));
  updateLength();
  return *this;
}

Packet &Packet::appendPayload(const uint8_t *buffer, std::size_t length) {
  return appendPayload(utils::MemBuf::copyBuffer(buffer, length));
}

Packet &Packet::appendHeader(std::unique_ptr<utils::MemBuf> &&header) {
  if (!payload_head_) {
    header_head_->prependChain(std::move(header));
  } else {
    payload_head_->prependChain(std::move(header));
  }

  updateLength();
  return *this;
}

Packet &Packet::appendHeader(const uint8_t *buffer, std::size_t length) {
  return appendHeader(utils::MemBuf::copyBuffer(buffer, length));
}

utils::Array<uint8_t> Packet::getPayload() const {
  if (TRANSPORT_EXPECT_FALSE(payload_head_ == nullptr)) {
    return utils::Array<uint8_t>();
  }

  // Hopefully the payload is contiguous
  if (TRANSPORT_EXPECT_FALSE(payload_head_->next() != header_head_)) {
    payload_head_->gather(payloadSize());
  }

  return utils::Array<uint8_t>(payload_head_->writableData(),
                               payload_head_->length());
}

Packet &Packet::updateLength(std::size_t length) {
  std::size_t total_length = length;

  for (utils::MemBuf *current = payload_head_;
       current && current != header_head_; current = current->next()) {
    total_length += current->length();
  }

  if (hicn_packet_set_payload_length(format_, (hicn_header_t *)packet_start_,
                                     total_length) < 0) {
    throw errors::RuntimeException("Error setting the packet payload.");
  }

  return *this;
}

PayloadType Packet::getPayloadType() const {
  hicn_payload_type_t ret = HPT_UNSPEC;

  if (hicn_packet_get_payload_type((hicn_header_t *)packet_start_, &ret) < 0) {
    throw errors::RuntimeException("Impossible to retrieve payload type.");
  }

  return PayloadType(ret);
}

Packet &Packet::setPayloadType(PayloadType payload_type) {
  if (hicn_packet_set_payload_type((hicn_header_t *)packet_start_,
                                   hicn_payload_type_t(payload_type)) < 0) {
    throw errors::RuntimeException("Error setting payload type of the packet.");
  }

  return *this;
}

Packet::Format Packet::getFormat() const {
  if (format_ == HF_UNSPEC) {
    if (hicn_packet_get_format((hicn_header_t *)packet_start_, &format_) < 0) {
      throw errors::MalformedPacketException();
    }
  }

  return format_;
}

const std::shared_ptr<utils::MemBuf> Packet::data() { return packet_; }

void Packet::dump() const {
  TRANSPORT_LOGI("The header length is: %zu", headerSize());
  TRANSPORT_LOGI("The payload length is: %zu", payloadSize());
  std::cerr << std::endl;

  hicn_packet_dump((uint8_t *)packet_->data(), headerSize());
  // hicn_packet_dump((uint8_t *)packet_->next()->data(), payloadSize());
}

void Packet::setSignatureSize(std::size_t size_bytes) {
  int ret = hicn_packet_set_signature_size(
      format_, (hicn_header_t *)packet_start_, size_bytes);

  if (ret < 0) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  packet_->append(size_bytes);
}

uint8_t *Packet::getSignature() const {
  uint8_t *signature;
  int ret = hicn_packet_get_signature(format_, (hicn_header_t *)packet_start_,
                                      &signature);

  if (ret < 0) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  return signature;
}

std::size_t Packet::getSignatureSize() const {
  size_t size_bytes;
  int ret = hicn_packet_get_signature_size(
      format_, (hicn_header_t *)packet_start_, &size_bytes);

  if (ret < 0) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  return size_bytes;
}

void Packet::setSignature(std::unique_ptr<utils::MemBuf> &&signature) {
  // Check if packet already contains a signature
  auto header = header_head_->next();
  while (header != payload_head_) {
    header->unlink();
    header = header->next();
  }

  appendHeader(std::move(signature));
}

void Packet::setSignatureTimestamp(const uint64_t &timestamp) {
  int ret = hicn_packet_set_signature_timestamp(
      format_, (hicn_header_t *)packet_start_, timestamp);

  if (ret < 0) {
    throw errors::RuntimeException("Error setting the signature timestamp.");
  }
}

uint64_t Packet::getSignatureTimestamp() const {
  uint64_t return_value;
  int ret = hicn_packet_get_signature_timestamp(
      format_, (hicn_header_t *)packet_start_, &return_value);

  if (ret < 0) {
    throw errors::RuntimeException("Error getting the signature timestamp.");
  }

  return return_value;
}

void Packet::setValidationAlgorithm(
    const utils::CryptoSuite &validation_algorithm) {
  int ret = hicn_packet_set_validation_algorithm(
      format_, (hicn_header_t *)packet_start_, uint8_t(validation_algorithm));

  if (ret < 0) {
    throw errors::RuntimeException("Error setting the validation algorithm.");
  }
}

utils::CryptoSuite Packet::getValidationAlgorithm() const {
  uint8_t return_value;
  int ret = hicn_packet_get_validation_algorithm(
      format_, (hicn_header_t *)packet_start_, &return_value);

  if (ret < 0) {
    throw errors::RuntimeException("Error getting the validation algorithm.");
  }

  return utils::CryptoSuite(return_value);
}

void Packet::setKeyId(const utils::KeyId &key_id) {
  int ret = hicn_packet_set_key_id(format_, (hicn_header_t *)packet_start_,
                                   key_id.first);

  if (ret < 0) {
    throw errors::RuntimeException("Error setting the key id.");
  }
}

utils::KeyId Packet::getKeyId() const {
  utils::KeyId return_value;
  int ret = hicn_packet_get_key_id(format_, (hicn_header_t *)packet_start_,
                                   &return_value.first, &return_value.second);

  if (ret < 0) {
    throw errors::RuntimeException("Error getting the validation algorithm.");
  }

  return return_value;
}

utils::CryptoHash Packet::computeDigest(HashAlgorithm algorithm) const {
  utils::CryptoHasher hasher(static_cast<utils::CryptoHashType>(algorithm));
  hasher.init();

  // Copy IP+TCP/ICMP header before zeroing them
  hicn_header_t header_copy;

  hicn_packet_copy_header(format_, (hicn_header_t *)packet_start_, &header_copy,
                          false);

  const_cast<Packet *>(this)->resetForHash();

  std::size_t payload_len = getPayloadSizeFromBuffer(format_, packet_start_);
  std::size_t header_length = getHeaderSizeFromFormat(format_);
  std::size_t signature_size = _is_ah(format_) ? getSignatureSize() : 0;

  hasher.updateBytes(packet_start_,
                     payload_len + header_length + signature_size);

  hicn_packet_copy_header(format_, &header_copy, (hicn_header_t *)packet_start_,
                          false);

  return hasher.finalize();
}

void Packet::setChecksum() {
  uint16_t partial_csum = 0;

  for (utils::MemBuf *current = header_head_->next();
       current && current != header_head_; current = current->next()) {
    if (partial_csum != 0) {
      partial_csum = ~partial_csum;
    }
    partial_csum = csum(current->data(), current->length(), partial_csum);
  }
  if (hicn_packet_compute_header_checksum(
          format_, (hicn_header_t *)packet_start_, partial_csum) < 0) {
    throw errors::MalformedPacketException();
  }
}

bool Packet::checkIntegrity() const {
  if (hicn_packet_check_integrity(format_, (hicn_header_t *)packet_start_) <
      0) {
    return false;
  }

  return true;
}

Packet &Packet::setSyn() {
  if (hicn_packet_set_syn((hicn_header_t *)packet_start_) < 0) {
    throw errors::RuntimeException("Error setting syn bit in the packet.");
  }

  return *this;
}

Packet &Packet::resetSyn() {
  if (hicn_packet_reset_syn((hicn_header_t *)packet_start_) < 0) {
    throw errors::RuntimeException("Error resetting syn bit in the packet.");
  }

  return *this;
}

bool Packet::testSyn() const {
  bool res = false;
  if (hicn_packet_test_syn((hicn_header_t *)packet_start_, &res) < 0) {
    throw errors::RuntimeException("Error testing syn bit in the packet.");
  }

  return res;
}

Packet &Packet::setAck() {
  if (hicn_packet_set_ack((hicn_header_t *)packet_start_) < 0) {
    throw errors::RuntimeException("Error setting ack bit in the packet.");
  }

  return *this;
}

Packet &Packet::resetAck() {
  if (hicn_packet_reset_ack((hicn_header_t *)packet_start_) < 0) {
    throw errors::RuntimeException("Error resetting ack bit in the packet.");
  }

  return *this;
}

bool Packet::testAck() const {
  bool res = false;
  if (hicn_packet_test_ack((hicn_header_t *)packet_start_, &res) < 0) {
    throw errors::RuntimeException("Error testing ack bit in the packet.");
  }

  return res;
}

Packet &Packet::setRst() {
  if (hicn_packet_set_rst((hicn_header_t *)packet_start_) < 0) {
    throw errors::RuntimeException("Error setting rst bit in the packet.");
  }

  return *this;
}

Packet &Packet::resetRst() {
  if (hicn_packet_reset_rst((hicn_header_t *)packet_start_) < 0) {
    throw errors::RuntimeException("Error resetting rst bit in the packet.");
  }

  return *this;
}

bool Packet::testRst() const {
  bool res = false;
  if (hicn_packet_test_rst((hicn_header_t *)packet_start_, &res) < 0) {
    throw errors::RuntimeException("Error testing rst bit in the packet.");
  }

  return res;
}

Packet &Packet::setFin() {
  if (hicn_packet_set_fin((hicn_header_t *)packet_start_) < 0) {
    throw errors::RuntimeException("Error setting fin bit in the packet.");
  }

  return *this;
}

Packet &Packet::resetFin() {
  if (hicn_packet_reset_fin((hicn_header_t *)packet_start_) < 0) {
    throw errors::RuntimeException("Error resetting fin bit in the packet.");
  }

  return *this;
}

bool Packet::testFin() const {
  bool res = false;
  if (hicn_packet_test_fin((hicn_header_t *)packet_start_, &res) < 0) {
    throw errors::RuntimeException("Error testing fin bit in the packet.");
  }

  return res;
}

Packet &Packet::resetFlags() {
  resetSyn();
  resetAck();
  resetRst();
  resetFin();

  return *this;
}

std::string Packet::printFlags() const {
  std::string flags = "";
  if (testSyn()) {
    flags += "S";
  }
  if (testAck()) {
    flags += "A";
  }
  if (testRst()) {
    flags += "R";
  }
  if (testFin()) {
    flags += "F";
  }
  return flags;
}

Packet &Packet::setSrcPort(uint16_t srcPort) {
  if (hicn_packet_set_src_port((hicn_header_t *)packet_start_, srcPort) < 0) {
    throw errors::RuntimeException("Error setting source port in the packet.");
  }

  return *this;
}

Packet &Packet::setDstPort(uint16_t dstPort) {
  if (hicn_packet_set_dst_port((hicn_header_t *)packet_start_, dstPort) < 0) {
    throw errors::RuntimeException(
        "Error setting destination port in the packet.");
  }

  return *this;
}

uint16_t Packet::getSrcPort() const {
  uint16_t port = 0;

  if (hicn_packet_get_src_port((hicn_header_t *)packet_start_, &port) < 0) {
    throw errors::RuntimeException("Error reading source port in the packet.");
  }

  return port;
}

uint16_t Packet::getDstPort() const {
  uint16_t port = 0;

  if (hicn_packet_get_dst_port((hicn_header_t *)packet_start_, &port) < 0) {
    throw errors::RuntimeException(
        "Error reading destination port in the packet.");
  }

  return port;
}

Packet &Packet::setTTL(uint8_t hops) {
  if (hicn_packet_set_hoplimit((hicn_header_t *)packet_start_, hops) < 0) {
    throw errors::RuntimeException("Error setting TTL.");
  }

  return *this;
}

uint8_t Packet::getTTL() const {
  uint8_t hops = 0;
  if (hicn_packet_get_hoplimit((hicn_header_t *)packet_start_, &hops) < 0) {
    throw errors::RuntimeException("Error reading TTL.");
  }

  return hops;
}

}  // end namespace core

}  // end namespace transport
