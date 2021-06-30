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

#include <glog/logging.h>
#include <hicn/transport/auth/crypto_hash.h>
#include <hicn/transport/core/packet.h>
#include <hicn/transport/errors/malformed_packet_exception.h>
#include <hicn/transport/utils/hash.h>

extern "C" {
#ifndef _WIN32
TRANSPORT_CLANG_DISABLE_WARNING("-Wextern-c-compat")
#endif
#include <hicn/error.h>
}

namespace transport {

namespace core {

const core::Name Packet::base_name("0::0|0");

Packet::Packet(Format format, std::size_t additional_header_size)
    : utils::MemBuf(utils::MemBuf(CREATE, 2048)),
      packet_start_(reinterpret_cast<hicn_header_t *>(writableData())),
      header_offset_(0),
      format_(format),
      payload_type_(PayloadType::UNSPECIFIED) {
  setFormat(format_, additional_header_size);
}

Packet::Packet(MemBuf &&buffer)
    : utils::MemBuf(std::move(buffer)),
      packet_start_(reinterpret_cast<hicn_header_t *>(writableData())),
      header_offset_(0),
      format_(getFormatFromBuffer(data(), length())),
      payload_type_(PayloadType::UNSPECIFIED) {}

Packet::Packet(CopyBufferOp, const uint8_t *buffer, std::size_t size)
    : utils::MemBuf(COPY_BUFFER, buffer, size),
      packet_start_(reinterpret_cast<hicn_header_t *>(writableData())),
      header_offset_(0),
      format_(getFormatFromBuffer(data(), length())),
      payload_type_(PayloadType::UNSPECIFIED) {}

Packet::Packet(WrapBufferOp, uint8_t *buffer, std::size_t length,
               std::size_t size)
    : utils::MemBuf(WRAP_BUFFER, buffer, length, size),
      packet_start_(reinterpret_cast<hicn_header_t *>(writableData())),
      header_offset_(0),
      format_(getFormatFromBuffer(this->data(), this->length())),
      payload_type_(PayloadType::UNSPECIFIED) {}

Packet::Packet(CreateOp, uint8_t *buffer, std::size_t length, std::size_t size,
               Format format, std::size_t additional_header_size)
    : utils::MemBuf(WRAP_BUFFER, buffer, length, size),
      packet_start_(reinterpret_cast<hicn_header_t *>(writableData())),
      header_offset_(0),
      format_(format),
      payload_type_(PayloadType::UNSPECIFIED) {
  clear();
  setFormat(format_, additional_header_size);
}

Packet::Packet(const Packet &other)
    : utils::MemBuf(other),
      packet_start_(reinterpret_cast<hicn_header_t *>(writableData())),
      header_offset_(other.header_offset_),
      format_(other.format_),
      payload_type_(PayloadType::UNSPECIFIED) {}

Packet::Packet(Packet &&other)
    : utils::MemBuf(std::move(other)),
      packet_start_(other.packet_start_),
      header_offset_(other.header_offset_),
      format_(other.format_),
      payload_type_(PayloadType::UNSPECIFIED) {
  other.packet_start_ = nullptr;
  other.format_ = HF_UNSPEC;
  other.header_offset_ = 0;
}

Packet::~Packet() {}

Packet &Packet::operator=(const Packet &other) {
  if (this != &other) {
    *this = other;
    packet_start_ = reinterpret_cast<hicn_header_t *>(writableData());
  }

  return *this;
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

  if (TRANSPORT_EXPECT_FALSE(hicn_packet_test_ece(HF_INET6_TCP,
                                                  (const hicn_header_t *)buffer,
                                                  &is_interest) < 0)) {
    throw errors::RuntimeException(
        "Impossible to retrieve ece flag from packet");
  }

  return !is_interest;
}

void Packet::setFormat(Packet::Format format,
                       std::size_t additional_header_size) {
  format_ = format;
  if (hicn_packet_init_header(format_, packet_start_) < 0) {
    throw errors::RuntimeException("Unexpected error initializing the packet.");
  }

  auto header_size = getHeaderSizeFromFormat(format_);
  assert(header_size <= tailroom());
  append(header_size);

  assert(additional_header_size <= tailroom());
  append(additional_header_size);

  header_offset_ = length();
}

bool Packet::isInterest() { return Packet::isInterest(data()); }

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
  std::size_t ret = 0;

  if (length()) {
    ret = getPayloadSizeFromBuffer(format_,
                                   reinterpret_cast<uint8_t *>(packet_start_));
  }

  return ret;
}

std::size_t Packet::headerSize() const {
  if (header_offset_ == 0 && length()) {
    const_cast<Packet *>(this)->header_offset_ = getHeaderSizeFromBuffer(
        format_, reinterpret_cast<uint8_t *>(packet_start_));
  }

  return header_offset_;
}

Packet &Packet::appendPayload(std::unique_ptr<utils::MemBuf> &&payload) {
  prependChain(std::move(payload));
  updateLength();
  return *this;
}

Packet &Packet::appendPayload(const uint8_t *buffer, std::size_t length) {
  prependPayload(&buffer, &length);

  if (length) {
    appendPayload(utils::MemBuf::copyBuffer(buffer, length));
  }

  updateLength();
  return *this;
}

std::unique_ptr<utils::MemBuf> Packet::getPayload() const {
  auto ret = clone();
  ret->trimStart(headerSize());
  return ret;
}

Packet &Packet::updateLength(std::size_t length) {
  std::size_t total_length = length;

  const utils::MemBuf *current = this;
  do {
    total_length += current->length();
    current = current->next();
  } while (current != this);

  total_length -= headerSize();

  if (hicn_packet_set_payload_length(format_, packet_start_, total_length) <
      0) {
    throw errors::RuntimeException("Error setting the packet payload.");
  }

  return *this;
}

PayloadType Packet::getPayloadType() const {
  if (payload_type_ == PayloadType::UNSPECIFIED) {
    hicn_payload_type_t ret;
    if (hicn_packet_get_payload_type(packet_start_, &ret) < 0) {
      throw errors::RuntimeException("Impossible to retrieve payload type.");
    }

    payload_type_ = (PayloadType)ret;
  }

  return payload_type_;
}

Packet &Packet::setPayloadType(PayloadType payload_type) {
  if (hicn_packet_set_payload_type(packet_start_,
                                   hicn_payload_type_t(payload_type)) < 0) {
    throw errors::RuntimeException("Error setting payload type of the packet.");
  }

  payload_type_ = payload_type;

  return *this;
}

Packet::Format Packet::getFormat() const {
  /**
   * We check packet start because after a movement it will result in a nullptr
   */
  if (format_ == HF_UNSPEC && length()) {
    if (hicn_packet_get_format(packet_start_, &format_) < 0) {
      LOG(ERROR) << "Unexpected packet format HF_UNSPEC.";
    }
  }

  return format_;
}

std::shared_ptr<utils::MemBuf> Packet::acquireMemBufReference() {
  return std::static_pointer_cast<utils::MemBuf>(shared_from_this());
}

void Packet::dump() const {
  LOG(INFO) << "HEADER -- Length: " << headerSize();
  LOG(INFO) << "PAYLOAD -- Length: " << payloadSize();

  const utils::MemBuf *current = this;
  do {
    LOG(INFO) << "MemBuf Length: " << current->length();
    dump((uint8_t *)current->data(), current->length());
    current = current->next();
  } while (current != this);
}

void Packet::dump(uint8_t *buffer, std::size_t length) {
  hicn_packet_dump(buffer, length);
}

void Packet::setSignatureSize(std::size_t size_bytes) {
  if (!authenticationHeader()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  int ret = hicn_packet_set_signature_size(format_, packet_start_, size_bytes);

  if (ret < 0) {
    throw errors::RuntimeException("Error setting signature size.");
  }
}

void Packet::setSignatureSizeGap(std::size_t size_bytes) {
  if (!authenticationHeader()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  int ret = hicn_packet_set_signature_gap(format_, packet_start_,
                                          (uint8_t)size_bytes);

  if (ret < 0) {
    throw errors::RuntimeException("Error setting signature size.");
  }
}

uint8_t *Packet::getSignature() const {
  if (!authenticationHeader()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  uint8_t *signature;
  int ret = hicn_packet_get_signature(format_, packet_start_, &signature);

  if (ret < 0) {
    throw errors::RuntimeException("Error getting signature.");
  }

  return signature;
}

void Packet::setSignatureTimestamp(const uint64_t &timestamp) {
  if (!authenticationHeader()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  int ret =
      hicn_packet_set_signature_timestamp(format_, packet_start_, timestamp);

  if (ret < 0) {
    throw errors::RuntimeException("Error setting the signature timestamp.");
  }
}

uint64_t Packet::getSignatureTimestamp() const {
  if (!authenticationHeader()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  uint64_t return_value;
  int ret = hicn_packet_get_signature_timestamp(format_, packet_start_,
                                                &return_value);

  if (ret < 0) {
    throw errors::RuntimeException("Error getting the signature timestamp.");
  }

  return return_value;
}

void Packet::setValidationAlgorithm(
    const auth::CryptoSuite &validation_algorithm) {
  if (!authenticationHeader()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  int ret = hicn_packet_set_validation_algorithm(format_, packet_start_,
                                                 uint8_t(validation_algorithm));

  if (ret < 0) {
    throw errors::RuntimeException("Error setting the validation algorithm.");
  }
}

auth::CryptoSuite Packet::getValidationAlgorithm() const {
  if (!authenticationHeader()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  uint8_t return_value;
  int ret = hicn_packet_get_validation_algorithm(format_, packet_start_,
                                                 &return_value);

  if (ret < 0) {
    throw errors::RuntimeException("Error getting the validation algorithm.");
  }

  return auth::CryptoSuite(return_value);
}

void Packet::setKeyId(const auth::KeyId &key_id) {
  if (!authenticationHeader()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  int ret = hicn_packet_set_key_id(format_, packet_start_, key_id.first);

  if (ret < 0) {
    throw errors::RuntimeException("Error setting the key id.");
  }
}

auth::KeyId Packet::getKeyId() const {
  if (!authenticationHeader()) {
    throw errors::RuntimeException("Packet without Authentication Header.");
  }

  auth::KeyId return_value;
  int ret = hicn_packet_get_key_id(format_, packet_start_, &return_value.first,
                                   &return_value.second);

  if (ret < 0) {
    throw errors::RuntimeException("Error getting the validation algorithm.");
  }

  return return_value;
}

auth::CryptoHash Packet::computeDigest(auth::CryptoHashType algorithm) const {
  auth::CryptoHash hash;
  hash.setType(algorithm);

  // Copy IP+TCP/ICMP header before zeroing them
  hicn_header_t header_copy;

  hicn_packet_copy_header(format_, packet_start_, &header_copy, false);

  const_cast<Packet *>(this)->resetForHash();

  hash.computeDigest(this);
  hicn_packet_copy_header(format_, &header_copy, packet_start_, false);

  return hash;
}

bool Packet::checkIntegrity() const {
  uint16_t partial_csum =
      csum(data() + HICN_V6_TCP_HDRLEN, length() - HICN_V6_TCP_HDRLEN, 0);

  for (const utils::MemBuf *current = next(); current != this;
       current = current->next()) {
    partial_csum = csum(current->data(), current->length(), ~partial_csum);
  }

  if (hicn_packet_check_integrity_no_payload(format_, packet_start_,
                                             partial_csum) < 0) {
    return false;
  }

  return true;
}

void Packet::prependPayload(const uint8_t **buffer, std::size_t *size) {
  auto last = prev();
  auto to_copy = std::min(*size, last->tailroom());
  std::memcpy(last->writableTail(), *buffer, to_copy);
  last->append(to_copy);
  *size -= to_copy;
  *buffer += to_copy;
}

Packet &Packet::setSyn() {
  if (hicn_packet_set_syn(format_, packet_start_) < 0) {
    throw errors::RuntimeException("Error setting syn bit in the packet.");
  }

  return *this;
}

Packet &Packet::resetSyn() {
  if (hicn_packet_reset_syn(format_, packet_start_) < 0) {
    throw errors::RuntimeException("Error resetting syn bit in the packet.");
  }

  return *this;
}

bool Packet::testSyn() const {
  bool res = false;
  if (hicn_packet_test_syn(format_, packet_start_, &res) < 0) {
    throw errors::RuntimeException("Error testing syn bit in the packet.");
  }

  return res;
}

Packet &Packet::setAck() {
  if (hicn_packet_set_ack(format_, packet_start_) < 0) {
    throw errors::RuntimeException("Error setting ack bit in the packet.");
  }

  return *this;
}

Packet &Packet::resetAck() {
  if (hicn_packet_reset_ack(format_, packet_start_) < 0) {
    throw errors::RuntimeException("Error resetting ack bit in the packet.");
  }

  return *this;
}

bool Packet::testAck() const {
  bool res = false;
  if (hicn_packet_test_ack(format_, packet_start_, &res) < 0) {
    throw errors::RuntimeException("Error testing ack bit in the packet.");
  }

  return res;
}

Packet &Packet::setRst() {
  if (hicn_packet_set_rst(format_, packet_start_) < 0) {
    throw errors::RuntimeException("Error setting rst bit in the packet.");
  }

  return *this;
}

Packet &Packet::resetRst() {
  if (hicn_packet_reset_rst(format_, packet_start_) < 0) {
    throw errors::RuntimeException("Error resetting rst bit in the packet.");
  }

  return *this;
}

bool Packet::testRst() const {
  bool res = false;
  if (hicn_packet_test_rst(format_, packet_start_, &res) < 0) {
    throw errors::RuntimeException("Error testing rst bit in the packet.");
  }

  return res;
}

Packet &Packet::setFin() {
  if (hicn_packet_set_fin(format_, packet_start_) < 0) {
    throw errors::RuntimeException("Error setting fin bit in the packet.");
  }

  return *this;
}

Packet &Packet::resetFin() {
  if (hicn_packet_reset_fin(format_, packet_start_) < 0) {
    throw errors::RuntimeException("Error resetting fin bit in the packet.");
  }

  return *this;
}

bool Packet::testFin() const {
  bool res = false;
  if (hicn_packet_test_fin(format_, packet_start_, &res) < 0) {
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
  std::string flags;

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
  if (hicn_packet_set_src_port(format_, packet_start_, srcPort) < 0) {
    throw errors::RuntimeException("Error setting source port in the packet.");
  }

  return *this;
}

Packet &Packet::setDstPort(uint16_t dstPort) {
  if (hicn_packet_set_dst_port(format_, packet_start_, dstPort) < 0) {
    throw errors::RuntimeException(
        "Error setting destination port in the packet.");
  }

  return *this;
}

uint16_t Packet::getSrcPort() const {
  uint16_t port = 0;

  if (hicn_packet_get_src_port(format_, packet_start_, &port) < 0) {
    throw errors::RuntimeException("Error reading source port in the packet.");
  }

  return port;
}

uint16_t Packet::getDstPort() const {
  uint16_t port = 0;

  if (hicn_packet_get_dst_port(format_, packet_start_, &port) < 0) {
    throw errors::RuntimeException(
        "Error reading destination port in the packet.");
  }

  return port;
}

Packet &Packet::setTTL(uint8_t hops) {
  if (hicn_packet_set_hoplimit(packet_start_, hops) < 0) {
    throw errors::RuntimeException("Error setting TTL.");
  }

  return *this;
}

uint8_t Packet::getTTL() const {
  uint8_t hops = 0;
  if (hicn_packet_get_hoplimit(packet_start_, &hops) < 0) {
    throw errors::RuntimeException("Error reading TTL.");
  }

  return hops;
}

}  // end namespace core

}  // end namespace transport
